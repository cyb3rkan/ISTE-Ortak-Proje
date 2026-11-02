"""
Provider adapter -> web mapper -> API DTO contract.

The web layer only forwards allow-listed summary fields. These tests run the
real adapters on fake provider answers (no network, fake key) and check what
reaches ``ProviderResultDTO.data_summary``: the fields the DTO promises are
filled from the adapters' real keys, a field the provider did not report is
absent or ``null`` (never invented as ``0``/``false``), and raw free text such
as abuse-report comments or service banners stays out.

Also covered: short fake secrets in error text, and the ``source`` of the AI
narrative (model vs deterministic fallback), which never touches the score.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from ioc_enricher.core.analyzer import AIAnalyzer
from ioc_enricher.enricher import IOCEnricher
from ioc_enricher.models import IOCType
from ioc_enricher.models.result import (
    AIAnalysis, EnrichmentResult, RiskLevel, RiskScore, ScoreBreakdown,
)
from ioc_enricher.providers import (
    AbuseIPDBProvider, ShodanProvider, VirusTotalProvider, ZeroBounceProvider,
)
from ioc_enricher.utils.cache import Cache
from ioc_enricher.utils.config import Config
from ioc_enricher.web.mappers import (
    sanitize_error_message, to_enrichment_dto, to_provider_result_dtos,
)

_KEY = "phase9-fake-key-c41d"
_IP = "203.0.113.7"          # RFC 5737 documentation address


class _NoWait:
    def wait(self, provider: str, max_wait=None) -> bool:
        return True

    def backoff(self, provider: str, delay=None) -> float:
        return 60.0


def _answer(cls, body, status: int = 200, method: str = "lookup_ip", ioc: str = _IP):
    provider = cls(api_key=_KEY, timeout=5, rate_limiter=_NoWait())
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = body
    resp.text = json.dumps(body)
    provider._session.request = MagicMock(return_value=resp)
    return getattr(provider, method)(ioc)


def _summary(result) -> dict:
    [dto] = to_provider_result_dtos({result.provider: result})
    assert _KEY not in json.dumps(dto.model_dump())
    return dto.data_summary


# ---------------------------------------------------------------------------
# Adapter -> mapper -> DTO
# ---------------------------------------------------------------------------

_SHODAN_HOST = {
    "ip_str": _IP, "ports": [22, 443], "hostnames": [], "domains": [],
    "org": "Example Hosting", "isp": "Example ISP", "asn": "AS64500",
    "country_code": "NL", "country_name": "Netherlands", "tags": [],
    "vulns": {"CVE-2024-0001": {"cvss": 7.5}, "CVE-2024-0002": {"cvss": 5.0}},
    "data": [{"port": 22, "transport": "tcp", "data": "SSH-2.0-BANNER-TEXT"}],
}


class TestProviderSummaryContract:

    def test_shodan_organisation_and_cve_count_reach_the_api(self):
        summary = _summary(_answer(ShodanProvider, _SHODAN_HOST))
        assert summary["org"] == "Example Hosting"
        assert summary["vulns_count"] == 2
        assert summary["ports"] == [22, 443]
        # Service banners are raw internet text: never forwarded.
        assert "BANNER-TEXT" not in json.dumps(summary)

    def test_shodan_host_without_cves_reports_zero(self):
        host = {k: v for k, v in _SHODAN_HOST.items() if k != "vulns"}
        assert _summary(_answer(ShodanProvider, host))["vulns_count"] == 0

    def test_shodan_domain_lookup_keeps_the_resolved_address_only(self):
        summary = _summary(_answer(
            ShodanProvider, {"evil.example": "203.0.113.9"},
            method="lookup_domain", ioc="evil.example"))
        assert summary == {"resolved_ip": "203.0.113.9"}   # no invented org / CVE count

    def test_zerobounce_summary_keeps_verdict_and_unknowns_without_personal_data(self):
        body = {
            "address": "user@example.com", "status": "do_not_mail", "sub_status": "toxic",
            "free_email": False, "catchall_domain": None, "did_you_mean": None,
            "domain": "example.com", "domain_age_days": "12", "mx_found": "true",
            "mx_record": "mx.example.com", "smtp_provider": "g-suite",
            "firstname": "Jane", "lastname": "Doe", "gender": "female",
        }
        summary = _summary(_answer(ZeroBounceProvider, body, method="lookup_email",
                                   ioc="user@example.com"))
        assert (summary["status"], summary["sub_status"]) == ("do_not_mail", "toxic")
        assert summary["free_email"] is False
        assert "catchall_domain" in summary
        assert summary["catchall_domain"] is None
        assert summary["mx_found"] is True
        assert summary["domain_age_days"] == 12
        assert not {"firstname", "lastname", "gender", "mx_record"} & set(summary)

    def test_virustotal_engines_without_a_result_reach_the_api(self):
        stats = {"malicious": 0, "suspicious": 0, "harmless": 60, "undetected": 10,
                 "timeout": 3, "type-unsupported": 2}
        body = {"data": {"id": _IP, "type": "ip_address",
                         "attributes": {"last_analysis_stats": stats}}}
        summary = _summary(_answer(VirusTotalProvider, body))
        assert summary["no_result_engines"] == 5
        assert summary["malicious_count"] == 0          # a real zero stays zero
        assert summary["total_engines"] == 70

    def test_abuseipdb_categories_reach_the_api_without_report_comments(self):
        report = {"reportedAt": "2026-10-01T00:00:00+00:00", "comment": "PRIVATE-REPORTER-TEXT",
                  "categories": [22, 18], "reporterCountryCode": "US"}
        body = {"data": {
            "ipAddress": _IP, "isPublic": True, "isWhitelisted": None,
            "abuseConfidenceScore": 87, "countryCode": "NL", "isp": "Example Hosting",
            "totalReports": 2, "numDistinctUsers": 2, "reports": [report, dict(report, categories=[14])],
        }}
        summary = _summary(_answer(AbuseIPDBProvider, body))
        assert summary["categories"] == [14, 18, 22]
        assert summary["is_whitelisted"] is None       # not looked up, not "false"
        assert "PRIVATE-REPORTER-TEXT" not in json.dumps(summary)

    def test_failed_provider_carries_no_fields(self):
        summary = _summary(_answer(ShodanProvider, {"error": "x"}, status=503))
        assert summary == {}


# ---------------------------------------------------------------------------
# Error text: short fake secrets
# ---------------------------------------------------------------------------

_FAKE_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl"


class TestErrorSanitizer:

    @pytest.mark.parametrize("message, secret, kept", [
        ("HTTP 401: api_key=abc123 is invalid", "abc123", ["HTTP 401", "api_key=", "is invalid"]),
        ("token: Zx9short expired", "Zx9short", ["token:", "expired"]),
        ("password=hunter2; retry", "hunter2", ["password=", "retry"]),
        ("secret=s3cr", "s3cr", ["secret="]),
        ("x-api-key: k1 rejected", "k1", ["x-api-key:", "rejected"]),
        ("Authorization: Bearer abc.def.ghi rejected", "abc.def.ghi", ["Authorization", "rejected"]),
        ("Authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz", ["Authorization"]),
        ("GET /v1/host?key=SHORTKEY1&page=2 failed", "SHORTKEY1", ["page=2", "failed"]),
        (f"upstream echoed {_FAKE_JWT} back", _FAKE_JWT, ["upstream echoed", "back"]),
        ("groq rejected gsk_" + "a1" * 12, "gsk_" + "a1" * 12, ["groq rejected"]),
    ])
    def test_short_fake_secrets_are_masked_and_the_message_stays_readable(self, message, secret, kept):
        out = sanitize_error_message(message)
        assert secret not in out
        for fragment in kept:
            assert fragment in out
        assert "***REDACTED***" in out

    @pytest.mark.parametrize("message", [
        "Rate limit exceeded (HTTP 429); Shodan paused for 60s.",
        "Request timed out after 30s.",
        "token expired",
        "Invalid response from VirusTotal: body is not a JSON object.",
        "HTTP 401: Shodan rejected the API key; not queried again until restart.",
    ])
    def test_ordinary_messages_are_unchanged(self, message):
        assert sanitize_error_message(message) == message


# ---------------------------------------------------------------------------
# AI narrative source
# ---------------------------------------------------------------------------

def _result(ai: AIAnalysis | None) -> EnrichmentResult:
    return EnrichmentResult(
        ioc=_IP, ioc_type=IOCType.IPV4, provider_results={},
        risk_score=RiskScore(score=21, level=RiskLevel.MEDIUM, breakdown=ScoreBreakdown(abuseipdb=21),
                             reasons=["AbuseIPDB: 87% confidence"], active_data_points=[],
                             detection_confidence=0.5),
        ai_analysis=ai, timestamp=datetime(2026, 10, 28, tzinfo=timezone.utc))


class _NoProviders(Config):
    VIRUSTOTAL_API_KEY = ABUSEIPDB_API_KEY = SHODAN_API_KEY = ""
    OTX_API_KEY = GREYNOISE_API_KEY = ZEROBOUNCE_API_KEY = ""


class TestAIAnalysisSource:

    def test_model_narrative_is_labelled_ai(self):
        dto = to_enrichment_dto(_result(AIAnalysis(summary="model text", ai_provider="groq")))
        assert dto.ai_analysis.source == "ai"

    def test_offline_fallback_from_the_real_analyzer_is_labelled_deterministic(self):
        # The analysis the enricher uses when an AI call is skipped, fails or
        # is rejected (with AI disabled there is no narrative at all).
        result = _result(None)
        result.ai_analysis = AIAnalyzer(enabled=False).offline_analysis(
            result.risk_score, ioc_type=IOCType.IPV4)
        assert to_enrichment_dto(result).ai_analysis.source == "deterministic"

    def test_disabled_ai_produces_no_narrative_to_label(self, tmp_path):
        enricher = IOCEnricher(config=_NoProviders, cache=Cache(cache_dir=tmp_path, enabled=False),
                               ai_enabled=False)
        assert to_enrichment_dto(enricher.enrich(_IP, use_cache=False)).ai_analysis is None

    @pytest.mark.parametrize("provider", ["", "unknown"])
    def test_unknown_origin_is_not_guessed(self, provider):
        dto = to_enrichment_dto(_result(AIAnalysis(summary="?", ai_provider=provider)))
        assert dto.ai_analysis.source is None

    def test_source_never_changes_the_score_or_the_evidence(self):
        ai = to_enrichment_dto(_result(AIAnalysis(summary="m", ai_provider="groq")))
        fallback = to_enrichment_dto(_result(AIAnalysis(summary="d", ai_provider="none")))
        none = to_enrichment_dto(_result(None))
        assert ai.risk.model_dump() == fallback.risk.model_dump() == none.risk.model_dump()
        assert ai.providers == fallback.providers == none.providers
