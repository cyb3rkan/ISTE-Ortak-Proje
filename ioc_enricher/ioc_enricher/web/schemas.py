"""
Pydantic v2 request / response DTOs for the web adapter layer.

These models are deliberately *narrower* than the internal dataclasses in
``ioc_enricher.models``: provider raw payloads, audit trails containing
prompt text, internal file paths and any secret-bearing fields are
**not** exposed here. See :mod:`ioc_enricher.web.mappers` for the safe
projection.
"""
from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Allowed-value catalogues (kept small and explicit on purpose)
# ---------------------------------------------------------------------------

# The set of values the web layer accepts on the wire. Internally these are
# mapped to the richer ``IOCType`` enum (MD5/SHA1/SHA256 are all surfaced
# externally as the umbrella ``hash``).
ALLOWED_IOC_TYPES: tuple[str, ...] = (
    "auto",
    "ipv4",
    "ipv6",
    "domain",
    "url",
    "hash",
    "email",
)

ALLOWED_REPORT_FORMATS: tuple[str, ...] = ("json", "markdown")

_MAX_IOC_LEN = 2048
_MAX_BATCH_SIZE = 50
_MAX_BATCH_TOTAL_CHARS = _MAX_IOC_LEN * _MAX_BATCH_SIZE


# ---------------------------------------------------------------------------
# Request DTOs
# ---------------------------------------------------------------------------

class EnrichRequest(BaseModel):
    """Single-IOC enrichment request."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    ioc: str = Field(..., description="Raw IOC string (will be sanitised).")
    ioc_type: Optional[str] = Field(
        default="auto",
        description="One of: auto, ipv4, ipv6, domain, url, hash, email.",
    )
    use_cache: bool = True
    save_report_format: Optional[str] = Field(
        default=None,
        description="If set, persist a report in this format. One of: json, markdown.",
    )

    @field_validator("ioc")
    @classmethod
    def _ioc_not_empty(cls, v: str) -> str:
        if v is None or not v.strip():
            raise ValueError("ioc cannot be empty")
        if len(v) > _MAX_IOC_LEN:
            raise ValueError(f"ioc exceeds maximum length ({_MAX_IOC_LEN} chars)")
        return v

    @field_validator("ioc_type")
    @classmethod
    def _ioc_type_allowed(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return "auto"
        v_norm = v.strip().lower()
        if v_norm not in ALLOWED_IOC_TYPES:
            raise ValueError(
                f"ioc_type must be one of {ALLOWED_IOC_TYPES}, got '{v}'"
            )
        return v_norm

    @field_validator("save_report_format")
    @classmethod
    def _report_format_allowed(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v_norm = v.strip().lower()
        if v_norm not in ALLOWED_REPORT_FORMATS:
            raise ValueError(
                f"save_report_format must be one of {ALLOWED_REPORT_FORMATS} or null"
            )
        return v_norm


class BatchEnrichRequest(BaseModel):
    """Batch enrichment request (size-capped, deduplicates inputs)."""

    model_config = ConfigDict(extra="forbid")

    iocs: List[str] = Field(..., min_length=1, max_length=_MAX_BATCH_SIZE)
    ioc_type: Optional[str] = "auto"
    use_cache: bool = True
    save_report_format: Optional[str] = None

    @field_validator("iocs")
    @classmethod
    def _normalize_iocs(cls, v: List[str]) -> List[str]:
        if not v:
            raise ValueError("iocs cannot be empty")
        cleaned = [s.strip() for s in v if isinstance(s, str) and s.strip()]
        if not cleaned:
            raise ValueError("iocs must contain at least one non-empty value")
        if any(len(s) > _MAX_IOC_LEN for s in cleaned):
            raise ValueError(
                f"each IOC must be <= {_MAX_IOC_LEN} chars"
            )
        total = sum(len(s) for s in cleaned)
        if total > _MAX_BATCH_TOTAL_CHARS:
            raise ValueError(
                f"total batch input exceeds {_MAX_BATCH_TOTAL_CHARS} chars"
            )
        if len(cleaned) > _MAX_BATCH_SIZE:
            raise ValueError(f"batch size exceeds {_MAX_BATCH_SIZE}")
        return cleaned

    # Reuse the single-request validators for the optional fields.
    _check_ioc_type = field_validator("ioc_type")(
        EnrichRequest._ioc_type_allowed.__func__  # type: ignore[attr-defined]
    )
    _check_report_format = field_validator("save_report_format")(
        EnrichRequest._report_format_allowed.__func__  # type: ignore[attr-defined]
    )

    @model_validator(mode="after")
    def _final_size_check(self) -> "BatchEnrichRequest":
        # The list validator already enforces this, but keep a belt-and-braces
        # check so future changes can't silently regress the cap.
        if len(self.iocs) > _MAX_BATCH_SIZE:
            raise ValueError(f"batch size exceeds {_MAX_BATCH_SIZE}")
        return self


# ---------------------------------------------------------------------------
# Response DTOs
# ---------------------------------------------------------------------------

class ScoreAdjustmentDTO(BaseModel):
    """One non-provider score component (URL pattern lift, floor, cap …)."""

    model_config = ConfigDict(extra="forbid")

    key: str
    label: str
    points: int


class RiskDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")

    score: Union[int, float]
    level: str
    reasons: List[str] = Field(default_factory=list)
    detection_confidence: Optional[float] = None
    active_data_points: Optional[List[str]] = None
    # Optional, backward-compatible numeric per-provider score contribution.
    # Only ever populated with the deterministic scorer's own breakdown values
    # (provider name -> integer points). No raw provider data, no secrets.
    breakdown: Optional[Dict[str, float]] = None
    # Optional qualitative summary of the evidence the scorer saw.
    # One of: "very_strong" | "strong" | "moderate" | "weak" | "none".
    evidence_strength: Optional[str] = None
    # True iff the IOC matches a known anti-malware test-file family (e.g. EICAR).
    is_known_test_file: Optional[bool] = None
    test_file_family: Optional[str] = None
    # Human-readable note distinguishing operational risk from raw provider
    # verdicts when the IOC is a known test file.
    operational_risk_note: Optional[str] = None
    # VirusTotal malicious/total ratio (0..1) when available.
    vt_detection_ratio: Optional[float] = None
    # URL-mode pattern signals (canonical tokens). Empty / omitted for
    # non-URL IOCs. Backwards-compatible: older clients ignore unknown fields.
    url_pattern_signals: Optional[List[str]] = None
    # Provider category labels normalised to malicious tokens
    # (e.g. "known infection source", "malware"). May appear for any IOC
    # type when a provider returns categorical metadata.
    suspicious_categories: Optional[List[str]] = None
    # Canonical names of deterministic floors/boosts that fired on top of
    # the per-provider envelope. UI uses this to explain a final score
    # that exceeds the sum of provider contributions.
    applied_floors: Optional[List[str]] = None
    # Human-readable calibration note. Only present when the final score is
    # higher than the provider-only sum.
    calibration_note: Optional[str] = None
    # Itemised non-provider components. Invariant:
    # sum(breakdown.values()) + sum(points) == score.
    score_adjustments: Optional[List[ScoreAdjustmentDTO]] = None
    # "complete" | "partial" | "insufficient_data". Distinguishes absence of
    # evidence from evidence of benignness; does not change score/level.
    evidence_status: Optional[str] = None
    # {"queried", "responded", "failed", "not_found"} provider counts.
    provider_coverage: Optional[Dict[str, int]] = None
    # Names of providers that failed (error / timeout / rate limit).
    unavailable_providers: Optional[List[str]] = None


class ProviderResultDTO(BaseModel):
    """Web-safe summary of a single provider's response."""

    model_config = ConfigDict(extra="forbid")

    name: str
    status: str
    data_summary: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None
    response_time_ms: Optional[Union[int, float]] = None


class MitreTechniqueDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tactic: Optional[str] = None
    technique_id: Optional[str] = None
    technique_name: Optional[str] = None
    description: Optional[str] = None
    # "observed" | "reported" | "contextual" — how directly the evidence
    # supports the technique. Absent on older results.
    basis: Optional[str] = None
    # Short statement of the supporting provider signal.
    evidence: Optional[str] = None


class AIAnalysisDTO(BaseModel):
    """
    Web-safe projection of :class:`ioc_enricher.models.result.AIAnalysis`.

    Only fields with stable shapes and no secret leakage are exposed.
    Notably ``audit_trail`` is exposed without prompts/responses; only call
    metadata such as model name and token counts are included.
    """

    model_config = ConfigDict(extra="forbid")

    summary: str = ""
    key_findings: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    analyst_note: str = ""
    detection_confidence: float = 0.0
    ai_confidence: float = 0.0
    requires_human_review: bool = False
    why_malicious: List[str] = Field(default_factory=list)
    why_benign: List[str] = Field(default_factory=list)
    weak_signals: List[Dict[str, str]] = Field(default_factory=list)
    prioritized_recommendations: List[Dict[str, str]] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    confidence: float = 0.0
    audit_trail: Optional[Dict[str, Any]] = None
    # "ai" = validated model narrative; "deterministic" = rule-based fallback
    # (AI disabled, skipped, failed or rejected — audit_trail may still show
    # the attempted call). None when the result does not record it. Purely
    # descriptive: never changes the score, level or evidence.
    source: Optional[Literal["ai", "deterministic"]] = None


class EnrichmentDTO(BaseModel):
    """Top-level web response for a single enriched IOC."""

    model_config = ConfigDict(extra="forbid")

    ioc: str
    ioc_type: str
    risk: RiskDTO
    providers: List[ProviderResultDTO] = Field(default_factory=list)
    mitre: List[MitreTechniqueDTO] = Field(default_factory=list)
    ai_analysis: Optional[AIAnalysisDTO] = None
    meta: Dict[str, Any] = Field(default_factory=dict)
    report_id: Optional[str] = None


class BatchEnrichResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    results: List[EnrichmentDTO] = Field(default_factory=list)
    errors: List[Dict[str, Any]] = Field(default_factory=list)
    summary: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Provider / cache status DTOs
# ---------------------------------------------------------------------------

class ProviderStatusDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    enabled: bool
    configured: bool
    status: str
    last_error: Optional[str] = None


class ProviderStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    providers: List[ProviderStatusDTO] = Field(default_factory=list)
    ai_enabled: bool = False


class CacheStatsDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entries: int = 0
    hits: Optional[int] = None
    misses: Optional[int] = None
    size_bytes: Optional[int] = None
    ttl_hours: Optional[float] = None
