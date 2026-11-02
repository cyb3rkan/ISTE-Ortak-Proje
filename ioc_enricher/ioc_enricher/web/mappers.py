"""
Çekirdek ``EnrichmentResult`` → web DTO eşlemesi; güvenlik odaklı sanitizasyon.

Bu mapper'lar tarafından üretilen her değer, güvensiz bir istemciye HTTP sınırları
üzerinden güvenle gönderilebilecek şekilde tasarlanmıştır:

- Ham provider payload'ları yok — sadece provider başına beyaz listeye alınmış güvenli özet.
- Hata alanlarında dahili dosya yolları, stack trace'ler veya Python traceback'leri yok.
- API anahtarları / token'lar / parolalar yok — bilinen sır desenleri hem anahtarlar
  hem de string değerler içinde karartılır.
- Yanıt boyutunu sınırlamak için string'ler makul bir üst sınırda kısaltılır.
- IOC değerleri ham string olarak kalır; bunları HTML olarak render etmek çağıranın
  sorumluluğundadır — burada **HTML** üretilmez.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from ..models.result import AIAnalysis, EnrichmentResult, ProviderResult
from .schemas import (
    AIAnalysisDTO,
    EnrichmentDTO,
    MitreTechniqueDTO,
    ProviderResultDTO,
    RiskDTO,
    ScoreAdjustmentDTO,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MAX_STRING_LEN = 2048
_REDACTED = "***REDACTED***"

# Field names whose *values* are always redacted regardless of provider.
_SECRET_KEY_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)api[_\-]?key"),
    re.compile(r"(?i)apikey"),
    re.compile(r"(?i)secret"),
    re.compile(r"(?i)password"),
    re.compile(r"(?i)passwd"),
    re.compile(r"(?i)token"),
    re.compile(r"(?i)authorization"),
    re.compile(r"(?i)bearer"),
    re.compile(r"(?i)x-?api-?key"),
)

# Secrets *inside* a string value. A value after an explicit secret name
# ("api_key=", "token: ", "Authorization: Bearer ", "?key=") is masked
# whatever its length — short test keys and passwords are secrets too — while
# the name itself stays, so the message remains readable.
_KEYED_SECRET = re.compile(
    r"(?i)(?P<keep>\b(?:x-?api-?key|api[_\-]?key|apikey|access[_\-]?token|"
    r"refresh[_\-]?token|token|client[_\-]?secret|secret|password|passwd|pwd|"
    r"authorization|key)\b\s*[:=]\s*[\"']?(?:(?:bearer|basic)\s+)?)"
    r"[^\s\"',;&]+"
)
# "Bearer <credential>" / "Basic <credential>" without a "name:" in front.
_AUTH_SCHEME_SECRET = re.compile(
    r"(?i)(?P<keep>\b(?:bearer|basic)\s+)"
    r"(?!(?:token|api[_\-]?key|apikey|secret|password)\b)[A-Za-z0-9._~+/\-]+=*"
)
# Well-known credential shapes, wherever they appear.
_SECRET_SHAPES: tuple[re.Pattern[str], ...] = (
    # JSON Web Tokens.
    re.compile(r"\beyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]*"),
    # OpenAI-style keys.
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    # Groq keys (the AI layer's provider).
    re.compile(r"gsk_[A-Za-z0-9]{20,}"),
    # GitHub-style tokens.
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    # AWS-style access key IDs.
    re.compile(r"AKIA[0-9A-Z]{16}"),
)

# Patterns that look like absolute filesystem paths or tracebacks.
_PATH_LIKE_PATTERNS: tuple[re.Pattern[str], ...] = (
    # Windows drive paths: C:\Users\foo\bar
    re.compile(r"[A-Za-z]:\\(?:[^\\\n\"']+\\)+[^\\\n\"']+"),
    # POSIX absolute paths nested at least two levels deep.
    re.compile(r"/(?:home|root|usr|var|etc|opt|tmp|private)/[^\s\"']+"),
)

_TRACEBACK_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"Traceback \(most recent call last\)"),
    re.compile(r'\bFile "[^"]+", line \d+'),
    re.compile(r"^\s*at\s+\S+\s*\(.*?:\d+:\d+\)$", re.MULTILINE),
)


# ---------------------------------------------------------------------------
# Whitelist of safe summary fields per provider
# ---------------------------------------------------------------------------
#
# Anything *not* in this whitelist is dropped from the web response. Unknown
# providers fall back to a minimal "available_fields" listing so the caller
# can see *which* keys came back without seeing the values themselves.

_PROVIDER_SAFE_FIELDS: Dict[str, frozenset[str]] = {
    "VirusTotal": frozenset({
        "malicious", "suspicious", "harmless", "undetected", "timeout",
        "reputation", "total_scans", "categories", "type", "country",
        "as_owner", "asn",
        # Normalised counts (see virustotal provider) — needed so the UI
        # can mirror the VirusTotal web "X/Y engines flagged" verdict.
        "malicious_count", "suspicious_count", "total_engines",
        "harmless_count", "undetected_count",
        # Engines that timed out / failed / do not support the type: not in
        # total_engines, so "0/N" is read against the right denominator.
        "no_result_engines",
        # URL-specific extras.
        "status", "content_type", "tags", "title", "last_analysis_date",
    }),
    "AbuseIPDB": frozenset({
        "abuse_confidence_score", "total_reports", "num_distinct_users",
        "country_code", "usage_type", "is_public", "is_whitelisted",
        "isp", "domain", "last_reported_at",
        # Distinct report category ids (report comments stay out).
        "categories",
    }),
    "Shodan": frozenset({
        "ports", "hostnames", "country_code", "country_name", "org",
        "isp", "asn", "os", "tags", "vulns_count", "last_update",
        # Domain lookups answer only with the resolved address.
        "resolved_ip",
    }),
    "AlienVault OTX": frozenset({
        "pulse_count", "reputation", "tags", "country_code",
        "malware_families", "industries",
    }),
    "OTX": frozenset({
        "pulse_count", "reputation", "tags", "country_code",
        "malware_families", "industries",
    }),
    "GreyNoise": frozenset({
        "classification", "noise", "riot", "name", "tags",
        "first_seen", "last_seen",
    }),
    "ZeroBounce": frozenset({
        "status", "sub_status", "free_email", "catchall_domain", "mx_found",
        "domain_age_days", "smtp_provider", "did_you_mean",
    }),
}

# Contract fields whose value the adapter stores under its own name. The
# contract key wins when the data carries it; otherwise the adapter field is
# used. A field neither carries stays absent (never invented as 0/False).
_FIELD_SOURCES: Dict[str, Dict[str, str]] = {
    "Shodan": {"org": "organization"},
}

# Contract counts derived from an adapter list — only when the list exists.
_COUNT_FIELDS: Dict[str, Dict[str, str]] = {
    "Shodan": {"vulns_count": "vulns"},
}


# ---------------------------------------------------------------------------
# Public mapping API
# ---------------------------------------------------------------------------

def to_enrichment_dto(
    result: EnrichmentResult,
    report_id: Optional[str] = None,
    request_id: Optional[str] = None,
) -> EnrichmentDTO:
    """Convert an internal :class:`EnrichmentResult` to a web-safe DTO."""

    meta: Dict[str, Any] = {
        "from_cache": result.from_cache,
        "execution_time_ms": round(result.execution_time * 1000.0, 3),
        "timestamp": result.timestamp.isoformat(),
    }
    if request_id is not None:
        meta["request_id"] = request_id

    return EnrichmentDTO(
        ioc=result.ioc,
        ioc_type=result.ioc_type.value,
        risk=to_risk_dto(result),
        providers=to_provider_result_dtos(result.provider_results),
        mitre=to_mitre_dtos(result),
        ai_analysis=to_ai_analysis_dto(result),
        meta=meta,
        report_id=report_id,
    )


def to_risk_dto(result: EnrichmentResult) -> RiskDTO:
    risk = result.risk_score
    # Optional fields are only populated when the scorer actually produced
    # them — older cached results may not have these attributes.
    evidence_strength = getattr(risk, "evidence_strength", None)
    is_known_test = getattr(risk, "is_known_test_file", None)
    test_family = getattr(risk, "test_file_family", None)
    op_note = getattr(risk, "operational_risk_note", None)
    vt_ratio = getattr(risk, "vt_detection_ratio", None)
    url_signals = getattr(risk, "url_pattern_signals", None)
    susp_cats = getattr(risk, "suspicious_categories", None)
    applied_floors = getattr(risk, "applied_floors", None)
    calibration_note = getattr(risk, "calibration_note", None)
    evidence_status = getattr(risk, "evidence_status", None)
    coverage = getattr(risk, "provider_coverage", None)
    unavailable = getattr(risk, "unavailable_providers", None)
    return RiskDTO(
        score=risk.score,
        level=risk.level.value,
        reasons=[_truncate(r) for r in risk.reasons],
        detection_confidence=risk.detection_confidence,
        active_data_points=list(risk.active_data_points or []) or None,
        breakdown=_safe_score_breakdown(risk),
        evidence_strength=evidence_strength if isinstance(evidence_strength, str) else None,
        is_known_test_file=bool(is_known_test) if is_known_test is not None else None,
        test_file_family=test_family if isinstance(test_family, str) else None,
        operational_risk_note=_truncate(op_note) if isinstance(op_note, str) else None,
        vt_detection_ratio=float(vt_ratio) if isinstance(vt_ratio, (int, float)) else None,
        url_pattern_signals=(
            [str(t)[:64] for t in url_signals][:16]
            if isinstance(url_signals, (list, tuple)) and url_signals else None
        ),
        suspicious_categories=(
            [str(c)[:64] for c in susp_cats][:16]
            if isinstance(susp_cats, (list, tuple)) and susp_cats else None
        ),
        applied_floors=(
            [str(f)[:96] for f in applied_floors][:16]
            if isinstance(applied_floors, (list, tuple)) and applied_floors else None
        ),
        calibration_note=(
            _truncate(calibration_note)
            if isinstance(calibration_note, str) and calibration_note else None
        ),
        score_adjustments=_safe_adjustments(getattr(risk, "score_adjustments", None)),
        evidence_status=(
            evidence_status if evidence_status in _EVIDENCE_STATUSES else None
        ),
        provider_coverage=(
            {k: int(v) for k, v in coverage.items()
             if isinstance(k, str) and isinstance(v, int) and not isinstance(v, bool)}
            if isinstance(coverage, dict) and coverage else None
        ),
        unavailable_providers=(
            [str(n)[:64] for n in unavailable][:16]
            if isinstance(unavailable, (list, tuple)) and unavailable else None
        ),
    )


_EVIDENCE_STATUSES = frozenset({"complete", "partial", "insufficient_data"})


def _safe_adjustments(items: Any) -> Optional[List[ScoreAdjustmentDTO]]:
    """Project itemised score adjustments; ``None`` when there are none."""
    if not isinstance(items, (list, tuple)) or not items:
        return None
    out: List[ScoreAdjustmentDTO] = []
    for item in items[:16]:
        points = getattr(item, "points", None)
        if isinstance(points, bool) or not isinstance(points, int):
            continue
        out.append(ScoreAdjustmentDTO(
            key=str(getattr(item, "key", ""))[:64],
            label=_truncate(getattr(item, "label", ""), 160),
            points=points,
        ))
    return out or None


# Provider attributes on the internal ScoreBreakdown dataclass that are safe
# to surface — these are deterministic integer point contributions only.
_BREAKDOWN_FIELDS: tuple[str, ...] = (
    "virustotal",
    "abuseipdb",
    "shodan",
    "otx",
    "greynoise",
    "zerobounce",
)


def _safe_score_breakdown(risk: Any) -> Optional[Dict[str, float]]:
    """
    Project the deterministic scorer's per-provider breakdown into a plain
    ``{provider: points}`` dict.

    Returns ``None`` when no breakdown object is present (older results, or a
    future scorer that does not produce one) so the frontend keeps its
    fallback rendering. Only numeric values are emitted; anything non-numeric
    is dropped defensively.
    """
    breakdown = getattr(risk, "breakdown", None)
    if breakdown is None:
        return None
    out: Dict[str, float] = {}
    for field_name in _BREAKDOWN_FIELDS:
        value = getattr(breakdown, field_name, None)
        if isinstance(value, bool):  # bool is a subclass of int — exclude it
            continue
        if isinstance(value, (int, float)):
            out[field_name] = float(value)
    return out or None


def to_provider_result_dtos(
    provider_results: Dict[str, ProviderResult],
) -> List[ProviderResultDTO]:
    out: List[ProviderResultDTO] = []
    for name, pr in (provider_results or {}).items():
        out.append(
            ProviderResultDTO(
                name=pr.provider or name,
                status=pr.status.value,
                data_summary=safe_provider_summary(
                    pr.provider or name, pr.data or {}
                ),
                error=sanitize_error_message(pr.error) if pr.error else None,
                response_time_ms=(
                    round(pr.response_time * 1000.0, 3)
                    if pr.response_time is not None
                    else None
                ),
            )
        )
    return out


_MITRE_BASES = frozenset({"observed", "reported", "contextual"})


def to_mitre_dtos(result: EnrichmentResult) -> List[MitreTechniqueDTO]:
    out: List[MitreTechniqueDTO] = []
    for entry in result.mitre_mappings or []:
        out.append(
            MitreTechniqueDTO(
                tactic=_truncate(entry.tactic) if entry.tactic else None,
                technique_id=_truncate(entry.technique_id) if entry.technique_id else None,
                technique_name=_truncate(entry.technique_name) if entry.technique_name else None,
                description=_truncate(entry.description) if entry.description else None,
                basis=(
                    entry.basis
                    if getattr(entry, "basis", None) in _MITRE_BASES else None
                ),
                evidence=(
                    _truncate(entry.evidence, 256)
                    if getattr(entry, "evidence", None) else None
                ),
            )
        )
    return out


def to_ai_analysis_dto(result: EnrichmentResult) -> Optional[AIAnalysisDTO]:
    ai: Optional[AIAnalysis] = result.ai_analysis
    if ai is None:
        return None

    prio = [
        {
            "action": _truncate(r.action),
            "priority": r.priority or "medium",
            "rationale": _truncate(r.rationale or ""),
        }
        for r in (ai.prioritized_recommendations or [])
    ]
    weak = [
        {
            "message": _truncate(ws.message or ""),
            "type": ws.signal_type or "weak_evidence",
        }
        for ws in (ai.weak_signals or [])
    ]

    # Audit trail: only safe call metadata — no prompts, no completions.
    audit_dict: Optional[Dict[str, Any]] = None
    if ai.audit_trail is not None:
        audit_dict = {
            "model": ai.audit_trail.model,
            "fields_sent": list(ai.audit_trail.fields_sent or []),
            "fields_redacted": list(ai.audit_trail.fields_redacted or []),
            "prompt_tokens": ai.audit_trail.prompt_tokens,
            "completion_tokens": ai.audit_trail.completion_tokens,
            "latency_s": round(ai.audit_trail.latency_s, 3),
            "timestamp": ai.audit_trail.timestamp.isoformat(),
        }

    return AIAnalysisDTO(
        summary=_truncate(ai.summary or ""),
        analyst_note=_truncate(ai.analyst_note or ""),
        key_findings=[_truncate(s) for s in (ai.key_findings or [])],
        recommendations=[_truncate(s) for s in (ai.recommendations or [])],
        prioritized_recommendations=prio,
        tags=list(ai.tags or []),
        detection_confidence=ai.detection_confidence,
        ai_confidence=ai.ai_confidence,
        requires_human_review=bool(ai.requires_human_review),
        why_malicious=[_truncate(s) for s in (ai.why_malicious or [])],
        why_benign=[_truncate(s) for s in (ai.why_benign or [])],
        weak_signals=weak,
        confidence=ai.ai_confidence,
        audit_trail=audit_dict,
        source=_ai_source(ai.ai_provider),
    )


def _ai_source(ai_provider: Any) -> Optional[str]:
    """
    Where the narrative came from: ``"deterministic"`` for the rule-based
    fallback (``ai_provider == "none"``, also when an AI call failed or its
    reply was rejected), ``"ai"`` for a validated model reply, ``None`` when
    the stored result does not say — the origin is never guessed.
    """
    if ai_provider == "none":
        return "deterministic"
    if isinstance(ai_provider, str) and ai_provider not in ("", "unknown"):
        return "ai"
    return None


# ---------------------------------------------------------------------------
# Sanitisation helpers
# ---------------------------------------------------------------------------

def sanitize_error_message(message: Optional[str]) -> Optional[str]:
    """
    Return a user-safe version of *message*.

    Strips internal paths, Python tracebacks, and any embedded secret-looking
    substrings. Always truncated to a safe upper bound.
    """
    if message is None:
        return None
    if not isinstance(message, str):
        message = str(message)

    cleaned = message

    for pattern in _TRACEBACK_PATTERNS:
        if pattern.search(cleaned):
            # Tüm traceback'i at. Sızan bir stack frame'dense kısa, genel bir not
            # çağırana daha faydalıdır.
            cleaned = "Provider ile iletişim sırasında dahili bir hata oluştu."
            break

    for pattern in _PATH_LIKE_PATTERNS:
        cleaned = pattern.sub(_REDACTED, cleaned)

    return _truncate(_scrub_secrets(cleaned))


def safe_provider_summary(provider_name: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Return a whitelisted, redacted summary of a single provider's data dict.

    The contract is:

    * If *provider_name* is in the known catalogue, only fields in its
      allow-list are kept.
    * For unknown providers, we list the available top-level field names
      (so debugging is still possible) but *do not* include their values.
    * In both cases all leaf values pass through :func:`_redact_value`
      which scrubs secret-shaped strings.
    """
    if not isinstance(data, dict):
        return {}

    whitelist = _PROVIDER_SAFE_FIELDS.get(provider_name)

    if whitelist is None:
        # Unknown provider: expose only the *shape*, not the values.
        return {
            "available_fields": sorted(
                k for k in data.keys() if isinstance(k, str)
            )[:50]
        }

    sources = _FIELD_SOURCES.get(provider_name, {})
    out: Dict[str, Any] = {}
    for key in whitelist:
        source = key if key in data else sources.get(key)
        if source is not None and source in data:
            out[key] = _redact_value(data[source])
    for key, list_key in _COUNT_FIELDS.get(provider_name, {}).items():
        if key not in out and isinstance(data.get(list_key), list):
            out[key] = len(data[list_key])
    return out


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _truncate(value: Any, limit: int = _MAX_STRING_LEN) -> str:
    if value is None:
        return ""
    s = value if isinstance(value, str) else str(value)
    if len(s) <= limit:
        return s
    return s[: limit - 1] + "…"


def _is_secret_key(key: str) -> bool:
    return any(p.search(key) for p in _SECRET_KEY_PATTERNS)


def _scrub_secrets(text: str) -> str:
    """Mask secret values (see :data:`_KEYED_SECRET`) and credential shapes."""
    text = _KEYED_SECRET.sub(lambda m: m.group("keep") + _REDACTED, text)
    text = _AUTH_SCHEME_SECRET.sub(lambda m: m.group("keep") + _REDACTED, text)
    for pattern in _SECRET_SHAPES:
        text = pattern.sub(_REDACTED, text)
    return text


def _redact_value(value: Any) -> Any:
    """Recursively redact secret-shaped strings inside nested structures."""
    if isinstance(value, str):
        return _truncate(_scrub_secrets(value))
    if isinstance(value, dict):
        return {
            k: (_REDACTED if isinstance(k, str) and _is_secret_key(k) else _redact_value(v))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_redact_value(v) for v in value]
    return value
