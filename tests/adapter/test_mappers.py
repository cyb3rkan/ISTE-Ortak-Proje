"""
Unit tests for ``ioc_enricher.web.mappers``.

These tests exercise the DTO conversion *and* the security-focused
sanitisation: provider raw payloads must be whitelisted, secrets must be
redacted, internal paths and tracebacks must not leak.
"""
from __future__ import annotations

from datetime import datetime

import pytest

from ioc_enricher.models.ioc import IOCType
from ioc_enricher.models.result import (
    AIAnalysis,
    AIAuditTrail,
    EnrichmentResult,
    MITREEntry,
    ProviderResult,
    ProviderStatus,
    Recommendation,
    RiskLevel,
    RiskScore,
    ScoreBreakdown,
    WeakSignal,
)
from ioc_enricher.web.mappers import (
    safe_provider_summary,
    sanitize_error_message,
    to_enrichment_dto,
)

_SECRET_SHAPED_VALUE = "s" + "k-" + "LEAKED1234567890abcdef"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_result(provider_data: dict | None = None, ai: AIAnalysis | None = None) -> EnrichmentResult:
    provider_data = provider_data if provider_data is not None else {
        "malicious": 5,
        "total_scans": 70,
        "raw_xml": "<should-not-leak/>",
        "api_key": "dummy-provider-token-redaction-check",
    }
    pr = ProviderResult(
        provider="VirusTotal",
        status=ProviderStatus.SUCCESS,
        data=provider_data,
        error=None,
        response_time=0.42,
        timestamp=datetime(2026, 1, 1, 12, 0, 0),
    )
    risk = RiskScore(
        score=72,
        level=RiskLevel.HIGH,
        breakdown=ScoreBreakdown(virustotal=40, abuseipdb=32),
        reasons=["VT detected 5/70", "Reported by 12 distinct users"],
        active_data_points=["virustotal.malicious", "abuseipdb.total_reports"],
        detection_confidence=0.85,
    )
    mitre = [
        MITREEntry(
            tactic="Initial Access",
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            description="Adversaries may attempt to exploit a weakness.",
        )
    ]
    return EnrichmentResult(
        ioc="8.8.8.8",
        ioc_type=IOCType.IPV4,
        provider_results={"VirusTotal": pr},
        risk_score=risk,
        mitre_mappings=mitre,
        ai_analysis=ai,
        execution_time=1.234,
        timestamp=datetime(2026, 1, 1, 12, 0, 0),
        from_cache=False,
    )


# ---------------------------------------------------------------------------
# to_enrichment_dto
# ---------------------------------------------------------------------------

class TestToEnrichmentDTO:
    def test_basic_shape(self) -> None:
        dto = to_enrichment_dto(_make_result(), request_id="req-123")

        assert dto.ioc == "8.8.8.8"
        assert dto.ioc_type == "ipv4"
        assert dto.risk.score == 72
        assert dto.risk.level == "HIGH"
        assert dto.meta["request_id"] == "req-123"
        assert dto.meta["from_cache"] is False
        assert "execution_time_ms" in dto.meta
        assert dto.report_id is None

    def test_mitre_mapping(self) -> None:
        dto = to_enrichment_dto(_make_result())
        assert len(dto.mitre) == 1
        assert dto.mitre[0].technique_id == "T1190"

    def test_provider_payload_is_whitelisted(self) -> None:
        dto = to_enrichment_dto(_make_result())
        assert len(dto.providers) == 1
        summary = dto.providers[0].data_summary
        # whitelisted fields kept
        assert summary.get("malicious") == 5
        assert summary.get("total_scans") == 70
        # raw fields dropped
        assert "raw_xml" not in summary
        assert "api_key" not in summary

    def test_ai_analysis_when_present(self) -> None:
        ai = AIAnalysis(
            summary="Likely malicious",
            analyst_note="Confirmed via VT + AbuseIPDB",
            key_findings=["High abuse score"],
            recommendations=["Block at firewall"],
            prioritized_recommendations=[
                Recommendation(action="Block IP", priority="high", rationale="See VT"),
            ],
            tags=["botnet"],
            detection_confidence=0.9,
            ai_confidence=0.78,
            requires_human_review=False,
            why_malicious=["VT 5/70 malicious"],
            why_benign=[],
            weak_signals=[WeakSignal(message="single source", signal_type="single_source")],
            audit_trail=AIAuditTrail(
                model="llama-3.1-8b-instant",
                fields_sent=["malicious", "total_reports"],
                fields_redacted=["hostname"],
                prompt_tokens=100,
                completion_tokens=200,
                latency_s=1.5,
                timestamp=datetime(2026, 1, 1, 12, 0, 0),
            ),
            ai_provider="groq",
        )
        dto = to_enrichment_dto(_make_result(ai=ai))
        assert dto.ai_analysis is not None
        assert dto.ai_analysis.summary == "Likely malicious"
        assert dto.ai_analysis.confidence == pytest.approx(0.78)
        assert dto.ai_analysis.prioritized_recommendations[0]["action"] == "Block IP"
        assert dto.ai_analysis.weak_signals[0]["type"] == "single_source"
        # Audit trail must contain ONLY metadata, no prompt/response content.
        at = dto.ai_analysis.audit_trail
        assert at is not None
        assert at["model"] == "llama-3.1-8b-instant"
        assert "prompt" not in at
        assert "response" not in at
        assert "completion" not in at

    def test_ai_analysis_absent_returns_none(self) -> None:
        dto = to_enrichment_dto(_make_result(ai=None))
        assert dto.ai_analysis is None

    def test_report_id_propagates(self) -> None:
        dto = to_enrichment_dto(
            _make_result(), report_id="11111111-1111-4111-8111-111111111111"
        )
        assert dto.report_id == "11111111-1111-4111-8111-111111111111"


# ---------------------------------------------------------------------------
# Risk score breakdown (Phase 5.0.2)
# ---------------------------------------------------------------------------

class TestRiskBreakdown:
    def test_numeric_breakdown_is_exposed(self) -> None:
        # _make_result uses ScoreBreakdown(virustotal=40, abuseipdb=32).
        dto = to_enrichment_dto(_make_result())
        assert dto.risk.breakdown is not None
        assert dto.risk.breakdown["virustotal"] == 40.0
        assert dto.risk.breakdown["abuseipdb"] == 32.0
        # Unset providers still appear with a zero contribution.
        assert dto.risk.breakdown["shodan"] == 0.0

    def test_breakdown_values_are_numeric(self) -> None:
        dto = to_enrichment_dto(_make_result())
        assert all(
            isinstance(v, float) for v in (dto.risk.breakdown or {}).values()
        )

    def test_breakdown_absent_when_no_breakdown_object(self) -> None:
        # A result whose RiskScore carries no breakdown -> DTO breakdown None,
        # so the frontend keeps its fallback rendering.
        result = _make_result()
        # Simulate an older/foreign scorer that produced no breakdown.
        object.__setattr__(result.risk_score, "breakdown", None)
        dto = to_enrichment_dto(result)
        assert dto.risk.breakdown is None

    def test_breakdown_does_not_leak_non_numeric(self) -> None:
        result = _make_result()

        class _FakeBreakdown:
            virustotal = 40
            abuseipdb = "not-a-number"  # must be dropped
            shodan = True  # bool excluded
            otx = 0
            greynoise = 0
            zerobounce = 0

        object.__setattr__(result.risk_score, "breakdown", _FakeBreakdown())
        dto = to_enrichment_dto(result)
        assert dto.risk.breakdown is not None
        assert "abuseipdb" not in dto.risk.breakdown
        assert "shodan" not in dto.risk.breakdown
        assert dto.risk.breakdown["virustotal"] == 40.0


# ---------------------------------------------------------------------------
# safe_provider_summary
# ---------------------------------------------------------------------------

class TestSafeProviderSummary:
    def test_known_provider_whitelist(self) -> None:
        out = safe_provider_summary(
            "VirusTotal",
            {"malicious": 3, "harmless": 65, "raw_response": "<xml/>", "secret": "x"},
        )
        assert out == {"malicious": 3, "harmless": 65}

    def test_unknown_provider_lists_field_names_only(self) -> None:
        out = safe_provider_summary(
            "ImaginaryFeed",
            {"score": 99, "raw_html": "<x/>", "token": "sk-abcd"},
        )
        assert set(out.keys()) == {"available_fields"}
        assert "score" in out["available_fields"]
        # No values leaked.
        for v in out.values():
            assert v != 99
            assert "sk-abcd" not in str(v)

    def test_secret_keys_inside_known_provider_get_redacted(self) -> None:
        # Even if a known provider's whitelist contains a field, secret-looking
        # nested dict keys must be redacted.
        out = safe_provider_summary(
            "Shodan",
            {"org": {"name": "AcmeISP", "api_key": "AKIAABCDEFGHIJKLMNOP"}},
        )
        org = out.get("org")
        assert isinstance(org, dict)
        assert org["name"] == "AcmeISP"
        assert org["api_key"] == "***REDACTED***"

    def test_non_dict_input_returns_empty(self) -> None:
        assert safe_provider_summary("VirusTotal", None) == {}  # type: ignore[arg-type]
        assert safe_provider_summary("VirusTotal", ["list"]) == {}  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# sanitize_error_message
# ---------------------------------------------------------------------------

class TestSanitizeErrorMessage:
    def test_none_passthrough(self) -> None:
        assert sanitize_error_message(None) is None

    def test_windows_path_stripped(self) -> None:
        msg = "Could not open C:\\Users\\victim\\.env for reading"
        out = sanitize_error_message(msg)
        assert "C:\\Users\\victim" not in (out or "")

    def test_posix_path_stripped(self) -> None:
        out = sanitize_error_message("config /home/secrets/keys.json missing")
        assert "/home/secrets" not in (out or "")

    def test_generic_api_key_pattern_redacted(self) -> None:
        # The error sanitiser scrubs any secret-shaped "api_key=..." substring
        # regardless of the key prefix.
        out = sanitize_error_message(
            f"Auth failed: api_key={_SECRET_SHAPED_VALUE} rejected"
        )
        assert out is not None
        assert _SECRET_SHAPED_VALUE not in out

    def test_groq_key_redacted_in_error(self) -> None:
        # A leaked Groq key in a provider/AI error must never reach the client.
        out = sanitize_error_message(
            "Groq auth failed: api_key=gsk-ABCDEFGHIJKLMNOPQRSTUVWX rejected"
        )
        assert out is not None
        assert "gsk-ABCDEFGHIJKLMNOPQRSTUVWX" not in out

    def test_generic_token_pattern(self) -> None:
        out = sanitize_error_message(
            "Bearer token=ABCDEFG1234567890QRSTUV failed"
        )
        assert out is not None
        assert "ABCDEFG1234567890QRSTUV" not in out

    def test_traceback_collapsed(self) -> None:
        msg = (
            'Traceback (most recent call last):\n'
            '  File "/opt/app/foo.py", line 42, in bar\n'
            '    raise RuntimeError("boom")\n'
            'RuntimeError: boom'
        )
        out = sanitize_error_message(msg)
        assert out is not None
        assert "Traceback" not in out
        assert "/opt/app/foo.py" not in out

    def test_truncates_long_messages(self) -> None:
        out = sanitize_error_message("x" * 10_000)
        assert out is not None
        assert len(out) <= 2049  # _MAX_STRING_LEN + ellipsis safety


class TestRiskDTOOptionalFields:
    """
    The optional risk fields (evidence_strength, EICAR metadata, vt ratio)
    must be projected onto the DTO when present, and absent otherwise.
    """

    def test_eicar_metadata_round_trips_to_dto(self) -> None:
        risk = RiskScore(
            score=90,
            level=RiskLevel.CRITICAL,
            breakdown=ScoreBreakdown(virustotal=30, otx=15),
            reasons=["EICAR test-file recognised."],
            active_data_points=[],
            detection_confidence=0.95,
            evidence_strength="very_strong",
            is_known_test_file=True,
            test_file_family="EICAR",
            operational_risk_note="This is the EICAR anti-malware test file.",
            vt_detection_ratio=0.87,
        )
        result = EnrichmentResult(
            ioc="44d88612fea8a8f36de82e1278abb02f",
            ioc_type=IOCType.MD5,
            provider_results={},
            risk_score=risk,
            mitre_mappings=[],
            ai_analysis=None,
            execution_time=0.5,
            timestamp=datetime(2026, 1, 1, 12, 0, 0),
            from_cache=False,
        )
        dto = to_enrichment_dto(result)
        assert dto.risk.evidence_strength == "very_strong"
        assert dto.risk.is_known_test_file is True
        assert dto.risk.test_file_family == "EICAR"
        assert dto.risk.operational_risk_note is not None
        assert "test file" in dto.risk.operational_risk_note.lower()
        assert dto.risk.vt_detection_ratio == 0.87

    def test_optional_fields_absent_when_not_set(self) -> None:
        risk = RiskScore(
            score=10,
            level=RiskLevel.LOW,
            breakdown=ScoreBreakdown(),
            reasons=[],
            active_data_points=[],
            detection_confidence=0.05,
        )
        result = EnrichmentResult(
            ioc="8.8.8.8",
            ioc_type=IOCType.IPV4,
            provider_results={},
            risk_score=risk,
            mitre_mappings=[],
            ai_analysis=None,
            execution_time=0.1,
            timestamp=datetime(2026, 1, 1, 12, 0, 0),
            from_cache=False,
        )
        dto = to_enrichment_dto(result)
        # Default RiskScore has is_known_test_file=False, so the DTO carries
        # False through — but the other optional fields stay None when unset.
        assert dto.risk.is_known_test_file is False
        assert dto.risk.test_file_family is None
        assert dto.risk.operational_risk_note is None
        assert dto.risk.evidence_strength is None
        assert dto.risk.vt_detection_ratio is None
