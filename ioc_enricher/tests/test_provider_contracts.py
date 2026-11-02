"""
Provider adapter contracts.

Each adapter turns a provider's documented API answer into the normalised
fields the scorer, the MITRE mapper and the web layer read. These tests pin
that contract against the providers' published API references. Every HTTP
call is answered by a local fake: no network, no real key, no live data.

* A broken 2xx body is an invalid response, never a successful (clean) one.
* "Answered, but no analysis / no record" (NOT_FOUND) stays apart from a
  verdict, from an error and from a provider that is not configured.
* Counts and flags reach the scorer only with their documented types.
* VirusTotal's detection ratio counts only engines that returned a verdict.
* Endpoints match the current references (GreyNoise v3 IP Lookup and
  Community API, OTX IPv6 indicator section).
"""
from __future__ import annotations

import json
import logging
from unittest.mock import MagicMock

import pytest
import requests

from ioc_enricher.core.scoring import RiskScorer
from ioc_enricher.enricher import IOCEnricher
from ioc_enricher.mitre.mapper import MITREMapper
from ioc_enricher.models import IOCType, ProviderStatus
from ioc_enricher.providers import (
    AbuseIPDBProvider,
    GreyNoiseProvider,
    OTXProvider,
    ShodanProvider,
    VirusTotalProvider,
    ZeroBounceProvider,
)
from ioc_enricher.utils.cache import Cache
from ioc_enricher.utils.config import Config

# A fake key: it must never show up in a result, an error or a log line.
_KEY = "phase5-fake-key-7f3a9c"
_IP = "203.0.113.7"       # RFC 5737 documentation address
_IP6 = "2001:db8::7"      # RFC 3849 documentation address
_HASH = "a" * 64


class _NoWait:
    """Rate-limiter stand-in: tests never sleep or share the global limiter."""

    def wait(self, provider: str, max_wait=None) -> bool:
        return True

    def backoff(self, provider: str, delay=None) -> float:
        return 60.0


def _provider(cls):
    return cls(api_key=_KEY, timeout=5, rate_limiter=_NoWait())


def _json(status: int, body) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = body
    resp.text = json.dumps(body)
    return resp


def _text(status: int, text: str) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.json.side_effect = ValueError("body is not JSON")
    resp.text = text
    return resp


def _serve(provider, *responses) -> MagicMock:
    """Answer the provider's HTTP calls in order; the mock records the URLs."""
    provider._session.request = MagicMock(side_effect=list(responses))
    return provider._session.request


def _urls(mock: MagicMock) -> list:
    return [c.args[1] for c in mock.call_args_list]


def _is_invalid(result, name: str) -> bool:
    return (
        result.status == ProviderStatus.ERROR
        and result.data is None
        and (result.error or "").startswith(f"Invalid response from {name}")
    )


def _score(name: str, result, ioc=_IP, ioc_type=IOCType.IPV4):
    return RiskScorer().score({name: result}, ioc_value=ioc, ioc_type=ioc_type)


_NO_EVIDENCE = {"queried": 1, "responded": 0, "failed": 0, "not_found": 1}

_LOOKUPS = [
    pytest.param(VirusTotalProvider, "lookup_ip", _IP, id="virustotal"),
    pytest.param(AbuseIPDBProvider, "lookup_ip", _IP, id="abuseipdb"),
    pytest.param(GreyNoiseProvider, "lookup_ip", _IP, id="greynoise"),
    pytest.param(OTXProvider, "lookup_ip", _IP, id="otx"),
    pytest.param(ShodanProvider, "lookup_ip", _IP, id="shodan"),
    pytest.param(ZeroBounceProvider, "lookup_email", "user@example.com", id="zerobounce"),
]


# ---------------------------------------------------------------------------
# Shared result states (every provider)
# ---------------------------------------------------------------------------

class TestResultStatesStayDistinct:

    @pytest.mark.parametrize("cls, method, ioc", _LOOKUPS)
    @pytest.mark.parametrize("http_status, expected", [
        pytest.param(429, ProviderStatus.RATE_LIMITED, id="429"),
        pytest.param(400, ProviderStatus.ERROR, id="400"),
        pytest.param(401, ProviderStatus.ERROR, id="401"),
        pytest.param(403, ProviderStatus.ERROR, id="403"),
        pytest.param(500, ProviderStatus.ERROR, id="500"),
        pytest.param(503, ProviderStatus.ERROR, id="503"),
    ])
    def test_http_failure_keeps_its_state(self, cls, method, ioc, http_status, expected):
        provider = _provider(cls)
        resp = _json(http_status, {"message": "failure"})
        _serve(provider, resp, resp)
        result = getattr(provider, method)(ioc)
        assert result.status == expected
        assert result.data is None

    @pytest.mark.parametrize("cls, method, ioc", _LOOKUPS)
    def test_404_is_no_record_not_success(self, cls, method, ioc):
        provider = _provider(cls)
        _serve(provider, _json(404, {"message": "not found"}))
        result = getattr(provider, method)(ioc)
        assert result.status == ProviderStatus.NOT_FOUND
        assert result.data is None

    @pytest.mark.parametrize("cls, method, ioc", _LOOKUPS)
    def test_timeout_is_a_timeout(self, cls, method, ioc):
        provider = _provider(cls)
        provider._session.request = MagicMock(
            side_effect=requests.exceptions.ReadTimeout("read timed out")
        )
        assert getattr(provider, method)(ioc).status == ProviderStatus.TIMEOUT

    @pytest.mark.parametrize("cls, method, ioc", _LOOKUPS)
    def test_network_error_never_carries_the_key(self, cls, method, ioc):
        provider = _provider(cls)
        provider._session.request = MagicMock(side_effect=requests.exceptions.ConnectionError(
            f"connection refused for https://api.example.test/?key={_KEY}"
        ))
        result = getattr(provider, method)(ioc)
        assert result.status == ProviderStatus.ERROR
        assert _KEY not in json.dumps(result.to_dict())

    @pytest.mark.parametrize("cls, method, ioc", _LOOKUPS)
    @pytest.mark.parametrize("make_response", [
        pytest.param(lambda: _text(200, "<html>upstream proxy error</html>"), id="html"),
        pytest.param(lambda: _text(200, ""), id="empty-body"),
        pytest.param(lambda: _json(200, []), id="json-array"),
        pytest.param(lambda: _json(200, None), id="json-null"),
        pytest.param(lambda: _json(200, "ok"), id="json-string"),
        pytest.param(lambda: _json(200, {}), id="empty-object"),
    ])
    def test_broken_body_is_an_invalid_response(self, cls, method, ioc, make_response):
        provider = _provider(cls)
        _serve(provider, make_response(), make_response())
        result = getattr(provider, method)(ioc)
        assert _is_invalid(result, provider.name)
        assert "upstream proxy error" not in (result.error or "")

    def test_broken_body_reaches_the_scorer_as_a_failure(self):
        provider = _provider(AbuseIPDBProvider)
        _serve(provider, _text(200, "<html>upstream proxy error</html>"))
        risk = _score("AbuseIPDB", provider.lookup_ip(_IP))
        assert risk.provider_coverage == {"queried": 1, "responded": 0, "failed": 1, "not_found": 0}
        assert risk.evidence_status == "insufficient_data"

    @pytest.mark.parametrize("cls, method, ioc", _LOOKUPS)
    def test_key_never_reaches_the_logs(self, cls, method, ioc, caplog):
        provider = _provider(cls)
        resp = _json(500, {"message": "error"})
        _serve(provider, resp, resp)
        with caplog.at_level(logging.DEBUG, logger="ioc_enricher"):
            getattr(provider, method)(ioc)
        assert caplog.records, "provider debug logging was not captured"
        assert _KEY not in caplog.text


# ---------------------------------------------------------------------------
# Field type helpers
# ---------------------------------------------------------------------------

class TestFieldTypes:

    @pytest.mark.parametrize("value, expected", [
        (0, 0), (42, 42), (5.0, 5), (None, None), (True, None), (False, None),
        ("5", None), (-1, None), (1.5, None), (float("nan"), None),
        (float("inf"), None), (10**12, None), ([3], None),
    ])
    def test_count(self, value, expected):
        from ioc_enricher.providers._fields import count
        assert count(value) == expected
        assert count(value) is None or type(count(value)) is int

    @pytest.mark.parametrize("value, expected", [
        (True, True), (False, False), ("true", None), ("false", None), (1, None), (None, None),
    ])
    def test_flag(self, value, expected):
        from ioc_enricher.providers._fields import flag
        assert flag(value) is expected


# ---------------------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------------------

def _vt(stats=None, **attributes):
    attrs = dict(attributes)
    if stats is not None:
        attrs["last_analysis_stats"] = stats
    return {"data": {"id": "x", "type": "file", "attributes": attrs}}


class TestVirusTotalContract:

    @pytest.mark.parametrize("method, ioc, path", [
        ("lookup_ip", _IP, f"ip_addresses/{_IP}"),
        ("lookup_domain", "example.com", "domains/example.com"),
        ("lookup_hash", _HASH, f"files/{_HASH}"),
        # URL identifier: base64url of the URL without "=" padding.
        ("lookup_url", "https://example.com/x", "urls/aHR0cHM6Ly9leGFtcGxlLmNvbS94"),
    ])
    def test_uses_the_documented_endpoint(self, method, ioc, path):
        provider = _provider(VirusTotalProvider)
        mock = _serve(provider, _json(200, _vt({"undetected": 60})))
        result = getattr(provider, method)(ioc)
        assert _urls(mock) == ["https://www.virustotal.com/api/v3/" + path]
        assert provider._session.headers["x-apikey"] == _KEY
        assert result.status == ProviderStatus.SUCCESS

    def test_engines_without_a_verdict_are_not_in_the_total(self):
        provider = _provider(VirusTotalProvider)
        _serve(provider, _json(200, _vt({
            "malicious": 10, "suspicious": 2, "harmless": 0, "undetected": 48,
            "timeout": 3, "confirmed-timeout": 1, "failure": 2, "type-unsupported": 14,
        })))
        result = provider.lookup_hash(_HASH)
        assert result.status == ProviderStatus.SUCCESS
        assert result.data["malicious_count"] == 10
        assert result.data["total_engines"] == 60
        assert result.data["no_result_engines"] == 20

    def test_url_timeouts_are_not_in_the_total(self):
        provider = _provider(VirusTotalProvider)
        _serve(provider, _json(200, _vt({
            "harmless": 60, "malicious": 2, "suspicious": 1, "undetected": 20, "timeout": 7,
        })))
        result = provider.lookup_url("https://example.com/x")
        assert (result.data["total_engines"], result.data["no_result_engines"]) == (83, 7)

    def test_ratio_reaching_the_scorer_uses_verdict_engines(self):
        provider = _provider(VirusTotalProvider)
        _serve(provider, _json(200, _vt(
            {"malicious": 10, "undetected": 50, "type-unsupported": 40}
        )))
        risk = _score("VirusTotal", provider.lookup_hash(_HASH), _HASH, IOCType.SHA256)
        assert risk.vt_detection_ratio == pytest.approx(10 / 60, abs=1e-4)

    @pytest.mark.parametrize("stats", [
        pytest.param({}, id="empty-stats-queued"),
        pytest.param(None, id="no-stats"),
        pytest.param({"harmless": 0, "malicious": 0, "suspicious": 0, "undetected": 0,
                      "timeout": 0}, id="all-zero"),
        pytest.param({"timeout": 5, "type-unsupported": 60, "failure": 1},
                     id="no-engine-could-analyse"),
    ])
    def test_no_completed_analysis_is_not_found_not_clean(self, stats):
        provider = _provider(VirusTotalProvider)
        _serve(provider, _json(200, _vt(stats, reputation=0)))
        result = provider.lookup_ip(_IP)
        assert result.status == ProviderStatus.NOT_FOUND
        assert result.data is None
        assert "no completed analysis" in result.error

    def test_hash_floor_counts_only_verdict_engines(self):
        # 13 detections, 47 undetected, 15 engines that cannot read the file
        # type. Counting those 15 as clean gave 13/75 = 17% (score 6, LOW);
        # among the engines with a verdict it is 13/60 = 22%, which meets the
        # existing 20% hash floor (score 55).
        provider = _provider(VirusTotalProvider)
        _serve(provider, _json(200, _vt(
            {"malicious": 13, "undetected": 47, "type-unsupported": 15}
        )))
        risk = _score("VirusTotal", provider.lookup_hash(_HASH), _HASH, IOCType.SHA256)
        assert risk.score == 55

    @pytest.mark.parametrize("stats", [
        pytest.param({}, id="queued"),
        # Was "0/66 engines flagged" with complete evidence: a clean verdict.
        pytest.param({"timeout": 6, "type-unsupported": 60}, id="no-engine-could-analyse"),
    ])
    def test_no_analysis_reaches_the_scorer_as_no_evidence(self, stats):
        provider = _provider(VirusTotalProvider)
        _serve(provider, _json(200, _vt(stats)))
        risk = _score("VirusTotal", provider.lookup_hash(_HASH), _HASH, IOCType.SHA256)
        assert risk.provider_coverage == _NO_EVIDENCE
        assert risk.evidence_status == "insufficient_data"
        assert not any("0/" in reason for reason in risk.reasons)

    @pytest.mark.parametrize("bad", [
        pytest.param(None, id="null"), pytest.param("5", id="text"),
        pytest.param(True, id="bool"), pytest.param(-1, id="negative"),
        pytest.param(1.5, id="fraction"), pytest.param(float("nan"), id="nan"),
        pytest.param(float("inf"), id="infinity"), pytest.param(10**12, id="absurd"),
    ])
    def test_untyped_engine_count_is_an_invalid_response(self, bad):
        provider = _provider(VirusTotalProvider)
        _serve(provider, _json(200, _vt({"malicious": bad, "undetected": 60})))
        assert _is_invalid(provider.lookup_ip(_IP), "VirusTotal")

    @pytest.mark.parametrize("body", [
        pytest.param({"data": None}, id="data-null"),
        pytest.param({"data": {"attributes": "x"}}, id="attributes-not-object"),
        pytest.param({"error": {"code": "NotFoundError", "message": "x"}}, id="error-object"),
        pytest.param(_vt("stats"), id="stats-not-object"),
    ])
    def test_unexpected_structure_is_an_invalid_response(self, body):
        provider = _provider(VirusTotalProvider)
        _serve(provider, _json(200, body))
        assert _is_invalid(provider.lookup_ip(_IP), "VirusTotal")

    def test_integral_float_counts_become_ints(self):
        provider = _provider(VirusTotalProvider)
        _serve(provider, _json(200, _vt({"malicious": 5.0, "undetected": 55.0})))
        data = provider.lookup_ip(_IP).data
        assert (data["malicious_count"], data["total_engines"]) == (5, 60)
        assert type(data["total_engines"]) is int

    def test_context_fields_reach_consumers_with_their_types(self):
        provider = _provider(VirusTotalProvider)
        _serve(provider, _json(200, _vt(
            {"malicious": 1, "undetected": 80},
            reputation=-20,
            last_http_response_code=float("nan"),
            last_http_response_headers={"Content-Type": "text/html"},
            categories={"Vendor A": "phishing", "Vendor B": 5, "Vendor C": None},
            tags=["phishing", 5, None, "x" * 100],
            title=["not", "text"],
        )))
        url = "https://example.com/login"
        result = provider.lookup_url(url)
        data = result.data
        assert data["reputation"] == -20
        assert data["status"] is None
        assert data["content_type"] == "text/html"
        assert data["categories"] == {"Vendor A": "phishing"}
        assert data["tags"] == ["phishing", "x" * 64]
        assert data["title"] is None
        _score("VirusTotal", result, url, IOCType.URL)  # consumers read it without crashing

    def test_hash_unknown_to_virustotal_keeps_its_message(self):
        provider = _provider(VirusTotalProvider)
        _serve(provider, _json(404, {"error": {"code": "NotFoundError", "message": "x"}}))
        result = provider.lookup_hash(_HASH)
        assert result.status == ProviderStatus.NOT_FOUND
        assert "not found" in result.error


# ---------------------------------------------------------------------------
# AbuseIPDB
# ---------------------------------------------------------------------------

def _abuse(**overrides):
    data = {
        "ipAddress": _IP, "isPublic": True, "ipVersion": 4, "isWhitelisted": None,
        "abuseConfidenceScore": 87, "countryCode": "NL", "countryName": "Netherlands",
        "usageType": "Data Center/Web Hosting/Transit", "isp": "Example Hosting",
        "domain": "example.net", "hostnames": [], "isTor": False,
        "totalReports": 42, "numDistinctUsers": 15,
        "lastReportedAt": "2026-10-01T00:00:00+00:00", "reports": [],
    }
    data.update(overrides)
    return {"data": data}


def _report(*categories):
    return {
        "reportedAt": "2026-10-01T00:00:00+00:00", "comment": "ssh brute force",
        "categories": list(categories), "reporterId": 1,
        "reporterCountryCode": "US", "reporterCountryName": "United States",
    }


class TestAbuseIPDBContract:

    def test_request_matches_the_check_endpoint(self):
        provider = _provider(AbuseIPDBProvider)
        mock = _serve(provider, _json(200, _abuse()))
        provider.lookup_ip(_IP)
        call = mock.call_args
        assert call.args[:2] == ("GET", "https://api.abuseipdb.com/api/v2/check")
        params = call.kwargs["params"]
        assert params["ipAddress"] == _IP
        assert 1 <= params["maxAgeInDays"] <= 365
        assert "verbose" in params
        assert provider._session.headers["Key"] == _KEY

    def test_valid_answer_is_typed(self):
        provider = _provider(AbuseIPDBProvider)
        _serve(provider, _json(200, _abuse(isTor=True)))
        data = provider.lookup_ip(_IP).data
        assert data["abuse_confidence_score"] == 87
        assert data["total_reports"] == 42
        assert data["num_distinct_users"] == 15
        assert data["is_tor"] is True
        assert data["is_whitelisted"] is None   # documented: null when no whitelist lookup ran

    def test_categories_cover_every_returned_report(self):
        provider = _provider(AbuseIPDBProvider)
        reports = [_report(18, 22) for _ in range(5)] + [_report(14), _report(21, 18)]
        _serve(provider, _json(200, _abuse(reports=reports)))
        data = provider.lookup_ip(_IP).data
        assert data["categories"] == [14, 18, 21, 22]
        assert len(data["recent_reports"]) == 5

    def test_category_ids_are_validated(self):
        provider = _provider(AbuseIPDBProvider)
        _serve(provider, _json(200, _abuse(reports=[
            _report(18, "22", True, -1, 0, 999, 2.0, None),
            dict(_report(), categories="14"),
        ])))
        data = provider.lookup_ip(_IP).data
        assert data["categories"] == [2, 18]
        assert data["recent_reports"][0]["categories"] == [18, 2]
        assert data["recent_reports"][1]["categories"] == []

    def test_mitre_sees_categories_beyond_the_first_five_reports(self):
        provider = _provider(AbuseIPDBProvider)
        reports = [_report(18) for _ in range(5)] + [_report(21)]
        _serve(provider, _json(200, _abuse(reports=reports)))
        result = provider.lookup_ip(_IP)
        ids = {e.technique_id for e in MITREMapper().map(IOCType.IPV4, {"AbuseIPDB": result})}
        assert "T1190" in ids   # category 21 (Web App Attack) is only in report six

    def test_no_reports_is_an_answer_not_an_error(self):
        provider = _provider(AbuseIPDBProvider)
        _serve(provider, _json(200, _abuse(
            abuseConfidenceScore=0, totalReports=0, numDistinctUsers=0,
            lastReportedAt=None, reports=[],
        )))
        result = provider.lookup_ip(_IP)
        assert result.status == ProviderStatus.SUCCESS
        assert (result.data["abuse_confidence_score"], result.data["categories"]) == (0, [])
        risk = _score("AbuseIPDB", result)
        assert risk.provider_coverage["responded"] == 1

    @pytest.mark.parametrize("field, bad", [
        ("abuseConfidenceScore", None), ("abuseConfidenceScore", "87"),
        ("abuseConfidenceScore", 101), ("abuseConfidenceScore", -1),
        ("abuseConfidenceScore", True), ("abuseConfidenceScore", float("nan")),
        ("totalReports", None), ("totalReports", "42"), ("totalReports", -3),
    ])
    def test_untyped_evidence_field_is_an_invalid_response(self, field, bad):
        provider = _provider(AbuseIPDBProvider)
        _serve(provider, _json(200, _abuse(**{field: bad})))
        assert _is_invalid(provider.lookup_ip(_IP), "AbuseIPDB")

    @pytest.mark.parametrize("body", [
        pytest.param({"data": None}, id="data-null"),
        pytest.param({"data": []}, id="data-list"),
        pytest.param({"data": {k: v for k, v in _abuse()["data"].items()
                               if k != "abuseConfidenceScore"}}, id="no-score"),
        pytest.param({"errors": [{"detail": "x", "status": 422}]}, id="errors-with-200"),
    ])
    def test_missing_evidence_is_an_invalid_response(self, body):
        provider = _provider(AbuseIPDBProvider)
        _serve(provider, _json(200, body))
        assert _is_invalid(provider.lookup_ip(_IP), "AbuseIPDB")

    def test_api_error_response_stays_an_error(self):
        provider = _provider(AbuseIPDBProvider)
        _serve(provider, _json(422, {"errors": [{"detail": "invalid", "status": 422}]}))
        result = provider.lookup_ip(_IP)
        assert (result.status, result.error) == (ProviderStatus.ERROR, "HTTP 422")

    def test_invalid_answer_never_reaches_the_scorer_as_a_value(self):
        provider = _provider(AbuseIPDBProvider)
        _serve(provider, _json(200, _abuse(abuseConfidenceScore=None)))
        risk = _score("AbuseIPDB", provider.lookup_ip(_IP))
        assert risk.provider_coverage["failed"] == 1
        assert risk.evidence_status == "insufficient_data"


# ---------------------------------------------------------------------------
# GreyNoise
# ---------------------------------------------------------------------------

_GN_IP_URL = "https://api.greynoise.io/v3/ip/"
_GN_COMMUNITY_URL = "https://api.greynoise.io/v3/community/"

_GN_SCANNER = {
    "classification": "malicious", "actor": "unknown",
    "first_seen": "2026-09-01", "last_seen": "2026-10-20",
    "tags": [{"id": "0000", "slug": "mirai", "name": "Mirai", "category": "worm",
              "intention": "malicious"}],
    "metadata": {"source_country_code": "NL", "organization": "Example Hosting",
                 "asn": "AS64500", "category": "hosting"},
    "tor": False, "vpn": True,
}

_GN_NOT_OBSERVED = {
    "ip": _IP, "noise": False, "riot": False,
    "message": "IP not observed scanning the internet or contained in RIOT data set.",
}


def _gn_lookup(scanner=None, business=None):
    """IP Lookup (GET /v3/ip/{ip}) body in the documented IPResponseV3 shape."""
    return {
        "ip": _IP,
        "business_service_intelligence": (
            {"found": False, "trust_level": "", "name": "", "category": ""}
            if business is None else {"found": True, **business}
        ),
        "internet_scanner_intelligence": (
            {"found": False, "classification": ""}
            if scanner is None else {"found": True, **scanner}
        ),
        "request_metadata": {"restricted_fields": []},
    }


def _gn_community(**overrides):
    """Community API (GET /v3/community/{ip}) 200 body."""
    body = {
        "ip": _IP, "noise": True, "riot": False, "classification": "unknown",
        "name": "unknown", "link": f"https://viz.greynoise.io/ip/{_IP}",
        "last_seen": "2026-10-20", "message": "Success",
    }
    body.update(overrides)
    return body


class TestGreyNoiseContract:

    def test_queries_the_documented_ip_lookup_endpoint(self):
        provider = _provider(GreyNoiseProvider)
        mock = _serve(provider, _json(200, _gn_lookup(scanner=_GN_SCANNER)))
        provider.lookup_ip(_IP)
        assert _urls(mock) == [_GN_IP_URL + _IP]
        assert provider._session.headers["key"] == _KEY

    def test_scanner_record_is_read_from_the_v3_schema(self):
        provider = _provider(GreyNoiseProvider)
        _serve(provider, _json(200, _gn_lookup(scanner=_GN_SCANNER)))
        result = provider.lookup_ip(_IP)
        assert result.status == ProviderStatus.SUCCESS
        data = result.data
        assert (data["noise"], data["riot"], data["classification"]) == (True, False, "malicious")
        assert data["tags"] == ["Mirai"]
        assert (data["country_code"], data["organization"], data["asn"], data["category"]) == (
            "NL", "Example Hosting", "AS64500", "hosting")
        assert (data["tor"], data["vpn"]) == (False, True)
        assert data["data_source"] == "ip_lookup"
        assert _score("GreyNoise", result).breakdown.greynoise == 10

    def test_business_service_record_is_riot(self):
        provider = _provider(GreyNoiseProvider)
        _serve(provider, _json(200, _gn_lookup(
            business={"trust_level": "1", "name": "Example DNS", "category": "public_dns"}
        )))
        data = provider.lookup_ip(_IP).data
        assert (data["noise"], data["riot"], data["name"]) == (False, True, "Example DNS")

    @pytest.mark.parametrize("make_response", [
        pytest.param(lambda: _json(404, _GN_NOT_OBSERVED), id="http-404"),
        pytest.param(lambda: _json(200, _gn_lookup()), id="found-false-in-both"),
    ])
    def test_no_record_is_not_found(self, make_response):
        provider = _provider(GreyNoiseProvider)
        _serve(provider, make_response())
        result = provider.lookup_ip(_IP)
        assert result.status == ProviderStatus.NOT_FOUND
        assert result.data is None
        assert "no record" in result.error

    def test_not_observed_is_no_evidence_for_the_scorer(self):
        provider = _provider(GreyNoiseProvider)
        _serve(provider, _json(404, _GN_NOT_OBSERVED))
        risk = _score("GreyNoise", provider.lookup_ip(_IP))
        assert risk.provider_coverage == _NO_EVIDENCE
        assert risk.evidence_status == "insufficient_data"

    def test_key_without_ip_lookup_uses_the_community_api(self):
        # 403 = no IP Lookup access for this key/plan. (401 = key rejected:
        # no fallback, see test_provider_limits.py.)
        provider = _provider(GreyNoiseProvider)
        mock = _serve(provider, _json(403, {"message": "Forbidden"}),
                      _json(200, _gn_community()))
        result = provider.lookup_ip(_IP)
        assert _urls(mock) == [_GN_IP_URL + _IP, _GN_COMMUNITY_URL + _IP]
        assert result.status == ProviderStatus.SUCCESS
        assert result.data["data_source"] == "community"

    def test_community_not_observed_is_not_found(self):
        provider = _provider(GreyNoiseProvider)
        _serve(provider, _json(403, {"message": "Forbidden"}), _json(404, _GN_NOT_OBSERVED))
        result = provider.lookup_ip(_IP)
        assert result.status == ProviderStatus.NOT_FOUND
        assert "no record" in result.error

    def test_community_fallback_is_ipv4_only(self):
        provider = _provider(GreyNoiseProvider)
        mock = _serve(provider, _json(403, {"message": "Forbidden"}),
                      _json(400, {"message": "Request is not a valid routable IPv4 address"}))
        result = provider.lookup_ip(_IP6)
        assert _urls(mock) == [_GN_IP_URL + _IP6]
        assert (result.status, result.error) == (ProviderStatus.ERROR, "HTTP 403")

    def test_scanning_alone_is_not_malicious(self):
        # GreyNoise: an IP seen scanning without malicious tags is "unknown".
        provider = _provider(GreyNoiseProvider)
        body = _gn_community()
        del body["classification"]
        _serve(provider, _json(200, body))
        result = provider.lookup_ip(_IP)
        assert result.data["classification"] == "unknown"
        assert _score("GreyNoise", result).breakdown.greynoise == 3

    @pytest.mark.parametrize("raw, expected", [
        ("MALICIOUS ", "malicious"), ("suspicious", "suspicious"), ("benign", "benign"),
        (None, "unknown"), (5, "unknown"), ("bogus", "unknown"),
    ])
    def test_classification_is_normalised(self, raw, expected):
        provider = _provider(GreyNoiseProvider)
        _serve(provider, _json(200, _gn_lookup(scanner=dict(_GN_SCANNER, classification=raw))))
        result = provider.lookup_ip(_IP)
        assert result.data["classification"] == expected
        _score("GreyNoise", result)  # the scorer reads it without crashing

    def test_dataset_left_out_of_the_answer_was_not_found(self):
        # e.g. a plan whose IP Lookup answer leaves Business Service Intelligence out
        provider = _provider(GreyNoiseProvider)
        body = _gn_lookup(scanner=_GN_SCANNER)
        del body["business_service_intelligence"]
        _serve(provider, _json(200, body))
        data = provider.lookup_ip(_IP).data
        assert (data["noise"], data["riot"]) == (True, False)

    def test_community_answer_without_noise_or_riot_is_no_record(self):
        provider = _provider(GreyNoiseProvider)
        _serve(provider, _json(200, _gn_community(noise=False, riot=False)))
        result = provider.lookup_ip(_IP)
        assert result.status == ProviderStatus.NOT_FOUND
        assert "no record" in result.error

    def test_unparseable_ip_gets_no_community_fallback(self):
        provider = _provider(GreyNoiseProvider)
        mock = _serve(provider, _json(403, {"message": "Forbidden"}),
                      _json(200, _gn_community()))
        result = provider.lookup_ip("not-an-ip")
        assert len(_urls(mock)) == 1
        assert result.error == "HTTP 403"

    @pytest.mark.parametrize("body", [
        pytest.param({"ip": _IP, "internet_scanner_intelligence": {"found": "yes"},
                      "business_service_intelligence": {"found": False}}, id="v3-flag-text"),
        pytest.param({"ip": _IP, "internet_scanner_intelligence": {"found": True},
                      "business_service_intelligence": "x"}, id="v3-dataset-not-object"),
        pytest.param(_gn_community(noise="true"), id="community-flag-text"),
        pytest.param({"ip": _IP, "message": "Success"}, id="no-dataset"),
    ])
    def test_untyped_flags_are_an_invalid_response(self, body):
        provider = _provider(GreyNoiseProvider)
        _serve(provider, _json(200, body))
        assert _is_invalid(provider.lookup_ip(_IP), "GreyNoise")


# ---------------------------------------------------------------------------
# AlienVault OTX
# ---------------------------------------------------------------------------

_OTX = "https://otx.alienvault.com/api/v1/indicators/"


def _otx(count=3, pulses=None, **extra):
    pulse_info = {"count": count,
                  "pulses": [{"name": "Campaign A", "author_name": "analyst"}]
                  if pulses is None else pulses}
    return {"pulse_info": pulse_info, "reputation": 0, **extra}


_OTX_LOOKUPS = [
    pytest.param("lookup_ip", _IP, id="ipv4"),
    pytest.param("lookup_domain", "example.com", id="domain"),
    pytest.param("lookup_hash", _HASH, id="hash"),
    pytest.param("lookup_url", "https://example.com/x", id="url"),
]


class TestOTXContract:

    @pytest.mark.parametrize("method, ioc, path", [
        ("lookup_ip", _IP, f"IPv4/{_IP}/general"),
        ("lookup_ip", _IP6, f"IPv6/{_IP6}/general"),
        ("lookup_domain", "example.com", "domain/example.com/general"),
        ("lookup_hash", _HASH, f"file/{_HASH}/general"),
    ])
    def test_uses_the_documented_indicator_section(self, method, ioc, path):
        provider = _provider(OTXProvider)
        mock = _serve(provider, _json(200, _otx()))
        getattr(provider, method)(ioc)
        assert _urls(mock) == [_OTX + path]
        assert provider._session.headers["X-OTX-API-KEY"] == _KEY

    def test_url_answer_is_typed(self):
        provider = _provider(OTXProvider)
        mock = _serve(provider, _json(200, _otx(count=2, domain="example.com", alexa=5)))
        data = provider.lookup_url("https://example.com/x").data
        assert (data["pulse_count"], data["domain"], data["alexa"]) == (2, "example.com", None)
        # One percent-encoded path segment. OTX does not document the URL
        # encoding, so this pins the existing behaviour only.
        assert _urls(mock) == [_OTX + "url/https%3A%2F%2Fexample.com%2Fx/general"]

    @pytest.mark.parametrize("method, ioc", _OTX_LOOKUPS)
    @pytest.mark.parametrize("http_status, expected", [
        pytest.param(404, ProviderStatus.NOT_FOUND, id="404"),
        pytest.param(400, ProviderStatus.ERROR, id="400"),
        pytest.param(403, ProviderStatus.ERROR, id="403"),
        pytest.param(429, ProviderStatus.RATE_LIMITED, id="429"),
    ])
    def test_failures_keep_their_state_for_every_indicator_type(
        self, method, ioc, http_status, expected
    ):
        provider = _provider(OTXProvider)
        _serve(provider, _json(http_status, {"detail": "x"}))
        result = getattr(provider, method)(ioc)
        assert (result.status, result.data) == (expected, None)

    def test_no_pulses_is_an_answer_not_an_error(self):
        provider = _provider(OTXProvider)
        _serve(provider, _json(200, _otx(count=0, pulses=[])))
        result = provider.lookup_ip(_IP)
        assert (result.status, result.data["pulse_count"]) == (ProviderStatus.SUCCESS, 0)
        assert _score("AlienVault OTX", result).provider_coverage["responded"] == 1

    @pytest.mark.parametrize("method, ioc", _OTX_LOOKUPS)
    @pytest.mark.parametrize("body", [
        pytest.param({"reputation": 0}, id="no-pulse-info"),
        pytest.param({"pulse_info": None}, id="pulse-info-null"),
        pytest.param({"pulse_info": {"pulses": []}}, id="no-count"),
        pytest.param(_otx(count=None), id="count-null"),
        pytest.param(_otx(count="3"), id="count-text"),
        pytest.param(_otx(count=-1), id="count-negative"),
    ])
    def test_missing_pulse_count_is_an_invalid_response(self, method, ioc, body):
        provider = _provider(OTXProvider)
        _serve(provider, _json(200, body))
        assert _is_invalid(getattr(provider, method)(ioc), "AlienVault OTX")

    def test_pulse_references_are_typed(self):
        provider = _provider(OTXProvider)
        _serve(provider, _json(200, _otx(
            count=2, pulses=["junk", {"name": "Campaign B", "author_name": 5}]
        )))
        result = provider.lookup_ip(_IP)
        assert result.status == ProviderStatus.SUCCESS
        assert result.data["pulse_references"] == [{"name": "Campaign B", "author": None}]


# ---------------------------------------------------------------------------
# Shodan
# ---------------------------------------------------------------------------

_SHODAN_HOST = {
    "ip_str": _IP, "ports": [22, 80], "hostnames": [], "domains": [],
    "org": "Example Hosting", "isp": "Example Hosting", "asn": "AS64500", "os": None,
    "country_code": "NL", "country_name": "Netherlands", "city": "Amsterdam",
    "tags": [], "last_update": "2026-10-20T00:00:00",
    "data": [{"port": 22, "transport": "tcp", "product": "OpenSSH", "version": "8.9",
              "data": "SSH-2.0-OpenSSH_8.9"}],
}


class TestShodanContract:

    def test_host_request_passes_the_key_as_a_query_parameter(self):
        provider = _provider(ShodanProvider)
        mock = _serve(provider, _json(200, _SHODAN_HOST))
        provider.lookup_ip(_IP)
        assert mock.call_args.args[1] == f"https://api.shodan.io/shodan/host/{_IP}"
        assert mock.call_args.kwargs["params"] == {"key": _KEY}

    def test_ports_and_vulns_are_typed(self):
        provider = _provider(ShodanProvider)
        _serve(provider, _json(200, dict(
            _SHODAN_HOST,
            ports=[22, 80, "443", True, -1, 70000, 3389.0, 22],
            vulns=["CVE-2024-0001", 5, None],
        )))
        result = provider.lookup_ip(_IP)
        assert result.data["ports"] == [22, 80, 3389]
        assert result.data["vulns"] == ["CVE-2024-0001"]
        assert result.data["organization"] == "Example Hosting"
        _score("Shodan", result)  # the scorer reads it without crashing

    def test_vulns_object_form_gives_cve_ids(self):
        provider = _provider(ShodanProvider)
        _serve(provider, _json(200, dict(_SHODAN_HOST, vulns={"CVE-2024-0002": {"cvss": 9.8}})))
        assert provider.lookup_ip(_IP).data["vulns"] == ["CVE-2024-0002"]

    @pytest.mark.parametrize("body", [
        pytest.param({"ip_str": _IP}, id="no-ports"),
        pytest.param(dict(_SHODAN_HOST, ports=None), id="ports-null"),
        pytest.param(dict(_SHODAN_HOST, ports="22"), id="ports-text"),
    ])
    def test_host_without_a_port_list_is_an_invalid_response(self, body):
        provider = _provider(ShodanProvider)
        _serve(provider, _json(200, body))
        assert _is_invalid(provider.lookup_ip(_IP), "Shodan")

    def test_host_unknown_to_shodan_is_not_found(self):
        provider = _provider(ShodanProvider)
        _serve(provider, _json(404, {"error": "No information available for that IP."}))
        result = provider.lookup_ip(_IP)
        assert result.status == ProviderStatus.NOT_FOUND
        assert "not found" in result.error

    def test_dns_resolve_request(self):
        provider = _provider(ShodanProvider)
        mock = _serve(provider, _json(200, {"example.com": "203.0.113.5"}))
        result = provider.lookup_domain("example.com")
        assert mock.call_args.args[1] == "https://api.shodan.io/dns/resolve"
        assert mock.call_args.kwargs["params"] == {"hostnames": "example.com", "key": _KEY}
        assert result.data == {"domain": "example.com", "resolved_ip": "203.0.113.5"}

    @pytest.mark.parametrize("http_status, expected", [
        pytest.param(404, ProviderStatus.NOT_FOUND, id="404"),
        pytest.param(401, ProviderStatus.ERROR, id="401"),
        pytest.param(429, ProviderStatus.RATE_LIMITED, id="429"),
    ])
    def test_dns_resolve_failures_keep_their_state(self, http_status, expected):
        provider = _provider(ShodanProvider)
        _serve(provider, _json(http_status, {"error": "x"}))
        result = provider.lookup_domain("example.com")
        assert (result.status, result.data) == (expected, None)

    def test_unresolvable_domain_is_not_found(self):
        provider = _provider(ShodanProvider)
        _serve(provider, _json(200, {"example.com": None}))
        assert provider.lookup_domain("example.com").status == ProviderStatus.NOT_FOUND

    @pytest.mark.parametrize("answer", [5, ["203.0.113.5"], {"ip": "x"}])
    def test_untyped_dns_answer_is_an_invalid_response(self, answer):
        provider = _provider(ShodanProvider)
        _serve(provider, _json(200, {"example.com": answer}))
        assert _is_invalid(provider.lookup_domain("example.com"), "Shodan")


# ---------------------------------------------------------------------------
# ZeroBounce
# ---------------------------------------------------------------------------

_ZB_ERROR = {"error": "Invalid API Key or your account ran out of credits"}


def _zb(**fields):
    # Shape of the documented v2/validate answer: domain_age_days and
    # mx_found arrive as strings, free_email / catchall_domain as booleans.
    base = {
        "address": "user@example.com", "status": "valid", "sub_status": "",
        "free_email": False, "catchall_domain": False, "did_you_mean": None,
        "account": "user", "domain": "example.com", "domain_age_days": "9000",
        "active_in_days": "30", "active_first_seen": "2026-02-25",
        "smtp_provider": "g-suite", "mx_found": "true", "mx_record": "mx.example.com",
        "firstname": "Jane", "lastname": "Doe", "gender": "female",
        "country": None, "region": None, "city": None, "zipcode": None,
        "processed_at": "2026-06-18 07:05:00.033",
    }
    base.update(fields)
    return base


def _zb_score(**fields):
    provider = _provider(ZeroBounceProvider)
    _serve(provider, _json(200, _zb(**fields)))
    result = provider.lookup_email("user@example.com")
    return _score("ZeroBounce", result, "user@example.com", IOCType.EMAIL)


class TestZeroBounceContract:

    def test_key_travels_in_a_post_form_body_never_in_the_url(self):
        provider = _provider(ZeroBounceProvider)
        mock = _serve(provider, _json(200, _zb()))
        provider.lookup_email("user@example.com")
        [call] = mock.call_args_list
        assert call.args[0] == "POST"
        assert call.args[1] == "https://api.zerobounce.net/v2/validate"
        assert call.kwargs["data"] == {"api_key": _KEY, "email": "user@example.com"}
        assert not call.kwargs.get("params")
        assert _KEY not in call.args[1]

    def test_valid_answer_is_typed(self):
        provider = _provider(ZeroBounceProvider)
        _serve(provider, _json(200, _zb(sub_status="role_based", status="do_not_mail")))
        data = provider.lookup_email("user@example.com").data
        assert (data["status"], data["sub_status"]) == ("do_not_mail", "role_based")
        assert (data["free_email"], data["catchall_domain"], data["mx_found"]) == (False, False, True)
        assert data["domain_age_days"] == 9000
        assert data["domain"] == "example.com"
        assert data["smtp_provider"] == "g-suite"

    def test_personal_data_is_not_kept(self):
        provider = _provider(ZeroBounceProvider)
        _serve(provider, _json(200, _zb()))
        data = provider.lookup_email("user@example.com").data
        for field in ("firstname", "lastname", "gender", "city", "region", "zipcode"):
            assert field not in data

    @pytest.mark.parametrize("mx_found, expected", [
        ("true", True), ("false", False), (True, True), (False, False),
        ("yes", None), (1, None), (None, None),
    ])
    def test_mx_found_accepts_documented_string_and_boolean_forms(self, mx_found, expected):
        provider = _provider(ZeroBounceProvider)
        _serve(provider, _json(200, _zb(mx_found=mx_found)))
        assert provider.lookup_email("user@example.com").data["mx_found"] is expected

    @pytest.mark.parametrize("age, expected", [
        ("3431", 3431), (12, 12), ("0", 0), (None, None), ("", None),
        ("-5", None), ("12.5", None), ("abc", None), (True, None),
    ])
    def test_domain_age_is_a_non_negative_integer_or_unknown(self, age, expected):
        provider = _provider(ZeroBounceProvider)
        _serve(provider, _json(200, _zb(domain_age_days=age)))
        assert provider.lookup_email("user@example.com").data["domain_age_days"] == expected

    def test_free_email_counts_only_as_a_json_boolean(self):
        provider = _provider(ZeroBounceProvider)
        _serve(provider, _json(200, _zb(free_email="true")))
        assert provider.lookup_email("user@example.com").data["free_email"] is None

    @pytest.mark.parametrize("body", [
        pytest.param({"address": "user@example.com"}, id="no-status"),
        pytest.param(_zb(status=None), id="status-null"),
        pytest.param(_zb(status=7), id="status-number"),
        pytest.param(_zb(status="totally_new"), id="status-undocumented"),
    ])
    def test_answer_without_a_documented_status_is_an_invalid_response(self, body):
        provider = _provider(ZeroBounceProvider)
        _serve(provider, _json(200, body))
        assert _is_invalid(provider.lookup_email("user@example.com"), "ZeroBounce")

    def test_status_is_case_normalised(self):
        provider = _provider(ZeroBounceProvider)
        _serve(provider, _json(200, _zb(status="Do_Not_Mail", sub_status="TOXIC")))
        data = provider.lookup_email("user@example.com").data
        assert (data["status"], data["sub_status"]) == ("do_not_mail", "toxic")

    def test_error_body_is_a_rejected_key_and_stops_further_queries(self):
        provider = _provider(ZeroBounceProvider)
        mock = _serve(provider, _json(200, _ZB_ERROR), _json(200, _zb()))
        first = provider.lookup_email("user@example.com")
        assert first.status == ProviderStatus.ERROR
        assert first.data is None
        assert "ZeroBounce" in first.error
        assert "credits" in first.error
        second = provider.lookup_email("other@example.com")
        assert second.status == ProviderStatus.ERROR
        assert len(mock.call_args_list) == 1  # nothing sent while the key is rejected

    def test_error_text_from_the_provider_is_not_echoed(self):
        provider = _provider(ZeroBounceProvider)
        _serve(provider, _json(200, {"error": f"<script>x</script> {_KEY}"}))
        result = provider.lookup_email("user@example.com")
        assert "<script>" not in result.error
        assert _KEY not in json.dumps(result.to_dict())


class TestZeroBounceScoring:

    @pytest.mark.parametrize("fields, points", [
        pytest.param({}, 0, id="valid"),
        pytest.param({"status": "invalid", "sub_status": "mailbox_not_found"}, 0, id="invalid"),
        pytest.param({"status": "catch-all"}, 0, id="catch-all"),
        pytest.param({"status": "unknown", "sub_status": "greylisted"}, 0, id="unknown"),
        pytest.param({"status": "do_not_mail", "sub_status": "role_based"}, 0, id="role-based"),
        pytest.param({"status": "do_not_mail", "sub_status": "toxic"}, 3, id="toxic"),
        pytest.param({"status": "spamtrap"}, 2, id="spamtrap"),
        pytest.param({"status": "abuse"}, 1, id="abuse"),
        pytest.param({"status": "do_not_mail", "sub_status": "disposable"}, 1, id="disposable"),
        pytest.param({"domain_age_days": "29"}, 1, id="domain-29-days"),
        pytest.param({"domain_age_days": "30"}, 0, id="domain-30-days"),
        pytest.param({"domain_age_days": None}, 0, id="domain-age-unknown"),
        pytest.param({"status": "do_not_mail", "sub_status": "toxic",
                      "domain_age_days": "3"}, 4, id="toxic-new-domain"),
    ])
    def test_points(self, fields, points):
        assert _zb_score(**fields).breakdown.zerobounce == points

    def test_points_cap_at_five(self):
        # spamtrap (2) + toxic (3) + new domain (1) = 6, capped to the
        # provider's 5-point envelope.
        risk = _zb_score(status="spamtrap", sub_status="toxic", domain_age_days="1")
        assert risk.breakdown.zerobounce == 5

    def test_toxic_explains_itself(self):
        risk = _zb_score(status="do_not_mail", sub_status="toxic")
        assert any("ZeroBounce" in r and "toxic" in r.lower() for r in risk.reasons)
        assert "ZeroBounce.sub_status=toxic" in risk.active_data_points

    def test_toxic_maps_phishing_as_contextual(self):
        provider = _provider(ZeroBounceProvider)
        _serve(provider, _json(200, _zb(status="do_not_mail", sub_status="toxic")))
        result = provider.lookup_email("user@example.com")
        entries = MITREMapper().map(IOCType.EMAIL, {"ZeroBounce": result})
        [entry] = [e for e in entries if e.technique_id == "T1566"]
        assert entry.basis == "contextual"

    def test_valid_address_maps_nothing(self):
        provider = _provider(ZeroBounceProvider)
        _serve(provider, _json(200, _zb()))
        result = provider.lookup_email("user@example.com")
        assert MITREMapper().map(IOCType.EMAIL, {"ZeroBounce": result}) == []


# ---------------------------------------------------------------------------
# Unconfigured providers and coverage
# ---------------------------------------------------------------------------

class _OnlyVirusTotal(Config):
    VIRUSTOTAL_API_KEY = _KEY
    ABUSEIPDB_API_KEY = ""
    SHODAN_API_KEY = ""
    OTX_API_KEY = ""
    GREYNOISE_API_KEY = ""
    ZEROBOUNCE_API_KEY = ""


class _NothingConfigured(_OnlyVirusTotal):
    VIRUSTOTAL_API_KEY = ""


class TestUnconfiguredProviders:
    """A provider without a key is never queried: it is not an answer."""

    @staticmethod
    def _enricher(config, tmp_path) -> IOCEnricher:
        enricher = IOCEnricher(
            config=config, cache=Cache(cache_dir=tmp_path, enabled=False), ai_enabled=False
        )
        for provider in enricher._providers:
            provider._limiter = _NoWait()
        return enricher

    def test_unconfigured_providers_are_absent_not_answers(self, tmp_path):
        enricher = self._enricher(_OnlyVirusTotal, tmp_path)
        [virustotal] = enricher._providers
        _serve(virustotal, _json(200, _vt({"harmless": 60, "undetected": 30})))
        result = enricher.enrich(_IP, use_cache=False)
        assert set(result.provider_results) == {"VirusTotal"}
        risk = result.risk_score
        assert risk.provider_coverage == {"queried": 1, "responded": 1, "failed": 0, "not_found": 0}
        assert risk.evidence_status == "complete"

    def test_nothing_configured_is_insufficient_data_not_clean(self, tmp_path):
        enricher = self._enricher(_NothingConfigured, tmp_path)
        result = enricher.enrich(_IP, use_cache=False)
        assert result.provider_results == {}
        risk = result.risk_score
        assert risk.provider_coverage == {"queried": 0, "responded": 0, "failed": 0, "not_found": 0}
        assert risk.evidence_status == "insufficient_data"
        assert not any("clean" in r.lower() or "0/" in r for r in risk.reasons)

    def test_configured_but_unanswered_is_a_failure_not_absence(self, tmp_path):
        enricher = self._enricher(_OnlyVirusTotal, tmp_path)
        [virustotal] = enricher._providers
        _serve(virustotal, _json(401, {"error": {"code": "WrongCredentialsError"}}))
        risk = enricher.enrich(_IP, use_cache=False).risk_score
        assert risk.provider_coverage == {"queried": 1, "responded": 0, "failed": 1, "not_found": 0}
        assert risk.unavailable_providers == ["VirusTotal"]
