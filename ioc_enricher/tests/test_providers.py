"""
Tests for provider base class and individual provider response parsing.

All external HTTP calls are mocked — no API keys required.
"""
import pytest
from unittest.mock import MagicMock, patch

from ioc_enricher.providers.virustotal import VirusTotalProvider
from ioc_enricher.providers.abuseipdb import AbuseIPDBProvider
from ioc_enricher.providers.shodan import ShodanProvider
from ioc_enricher.providers.otx import OTXProvider
from ioc_enricher.providers.greynoise import GreyNoiseProvider
from ioc_enricher.providers.zerobounce import ZeroBounceProvider
from ioc_enricher.models import IOCType, ProviderStatus
from ioc_enricher.utils.rate_limiter import RateLimiter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_response(json_data: dict, status_code: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data
    resp.text = str(json_data)
    return resp


def _patch_request(provider, json_data: dict, status_code: int = 200):
    """Patch the provider's session.request to return a mock response."""
    mock_resp = _mock_response(json_data, status_code)
    provider._session.request = MagicMock(return_value=mock_resp)
    return mock_resp


# ---------------------------------------------------------------------------
# Capability declarations
# ---------------------------------------------------------------------------

class TestProviderCapabilities:

    def test_virustotal_supports_ip(self):
        p = VirusTotalProvider("key")
        assert p.supports(IOCType.IPV4)
        assert p.supports(IOCType.IPV6)

    def test_virustotal_supports_hash(self):
        p = VirusTotalProvider("key")
        assert p.supports(IOCType.MD5)
        assert p.supports(IOCType.SHA256)

    def test_abuseipdb_supports_ip_only(self):
        p = AbuseIPDBProvider("key")
        assert p.supports(IOCType.IPV4)
        assert not p.supports(IOCType.DOMAIN)
        assert not p.supports(IOCType.MD5)

    def test_shodan_supports_domain(self):
        p = ShodanProvider("key")
        assert p.supports(IOCType.DOMAIN)

    def test_zerobounce_supports_email_only(self):
        p = ZeroBounceProvider("key")
        assert p.supports(IOCType.EMAIL)
        assert not p.supports(IOCType.IPV4)

    def test_greynoise_supports_ip_only(self):
        p = GreyNoiseProvider("key")
        assert p.supports(IOCType.IPV4)
        assert not p.supports(IOCType.DOMAIN)


# ---------------------------------------------------------------------------
# VirusTotal parsing
# ---------------------------------------------------------------------------

class TestVirusTotalProvider:

    VT_IP_RESPONSE = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 5,
                    "suspicious": 2,
                    "harmless": 60,
                    "undetected": 3,
                },
                "reputation": -20,
                "country": "US",
                "asn": 15169,
                "as_owner": "GOOGLE",
            }
        }
    }

    def _provider(self):
        # Own limiter per test: the 429 test's pause must not leak into the
        # next test through the process-wide default limiter.
        return VirusTotalProvider("fake-key", rate_limiter=RateLimiter())

    def test_lookup_ip_success(self):
        p = self._provider()
        _patch_request(p, self.VT_IP_RESPONSE)
        result = p.lookup_ip("8.8.8.8")
        assert result.is_success()
        assert result.data["malicious_count"] == 5
        assert result.data["suspicious_count"] == 2
        assert result.data["total_engines"] == 70
        assert result.data["country"] == "US"

    def test_lookup_ip_rate_limited(self):
        p = self._provider()
        _patch_request(p, {}, status_code=429)
        result = p.lookup_ip("1.2.3.4")
        assert result.status == ProviderStatus.RATE_LIMITED

    def test_lookup_ip_not_found(self):
        p = self._provider()
        _patch_request(p, {"error": "Not Found"}, status_code=404)
        result = p.lookup_ip("1.2.3.4")
        assert result.status == ProviderStatus.NOT_FOUND

    def test_lookup_hash_success(self):
        p = self._provider()
        _patch_request(p, {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 70, "suspicious": 0, "harmless": 0, "undetected": 0},
                    "md5": "abc", "sha1": "def", "sha256": "ghi",
                    "type_description": "PE32",
                    "size": 12345,
                }
            }
        })
        result = p.lookup_hash("abc123")
        assert result.is_success()
        assert result.data["malicious_count"] == 70

    def test_lookup_url_success(self):
        p = self._provider()
        _patch_request(p, {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 3, "suspicious": 0, "harmless": 65, "undetected": 2},
                    "reputation": -5,
                }
            }
        })
        result = p.lookup_url("https://malicious.example.com")
        assert result.is_success()
        assert result.data["malicious_count"] == 3


# ---------------------------------------------------------------------------
# AbuseIPDB parsing
# ---------------------------------------------------------------------------

class TestAbuseIPDBProvider:

    ABUSE_RESPONSE = {
        "data": {
            "ipAddress": "1.2.3.4",
            "abuseConfidenceScore": 87,
            "isWhitelisted": False,
            "isTor": True,
            "isPublic": True,
            "countryCode": "CN",
            "countryName": "China",
            "isp": "Malicious ISP",
            "totalReports": 42,
            "numDistinctUsers": 15,
            "lastReportedAt": "2024-01-01T00:00:00+00:00",
            "reports": [],
        }
    }

    def test_lookup_ip_success(self):
        p = AbuseIPDBProvider("key")
        _patch_request(p, self.ABUSE_RESPONSE)
        result = p.lookup_ip("1.2.3.4")
        assert result.is_success()
        assert result.data["abuse_confidence_score"] == 87
        assert result.data["is_tor"] is True
        assert result.data["total_reports"] == 42

    def test_domain_not_supported(self):
        p = AbuseIPDBProvider("key")
        result = p.lookup_domain("example.com")
        assert result.status == ProviderStatus.UNSUPPORTED


# ---------------------------------------------------------------------------
# GreyNoise parsing
# ---------------------------------------------------------------------------

class TestGreyNoiseProvider:

    GN_MALICIOUS = {
        "ip": "1.2.3.4",
        "noise": True,
        "riot": False,
        "classification": "malicious",
        "name": "MALICIOUS-ACTOR",
        "last_seen": "2024-01-15",
        "metadata": {
            "country_code": "RU",
            "organization": "Evil Corp",
            "asn": "AS12345",
            "tor": False,
            "vpn": True,
        },
        "tags": ["scanner", "brute-forcer"],
    }

    GN_RIOT = {
        "ip": "8.8.8.8",
        "noise": False,
        "riot": True,
        "name": "Google LLC",
        "link": "https://www.greynoise.io/viz/riot",
    }

    def test_malicious_classification(self):
        p = GreyNoiseProvider("key")
        _patch_request(p, self.GN_MALICIOUS)
        result = p.lookup_ip("1.2.3.4")
        assert result.is_success()
        assert result.data["classification"] == "malicious"
        assert result.data["noise"] is True
        assert result.data["riot"] is False

    def test_riot_classification(self):
        p = GreyNoiseProvider("key")
        _patch_request(p, self.GN_RIOT)
        result = p.lookup_ip("8.8.8.8")
        assert result.is_success()
        assert result.data["riot"] is True

    def test_not_found_is_no_record_not_success(self):
        # GreyNoise documents 404 as "unable to find a record": no evidence,
        # so NOT_FOUND rather than a successful "unknown" verdict.
        p = GreyNoiseProvider("key")
        _patch_request(p, {"message": "Not found"}, status_code=404)
        result = p.lookup_ip("1.2.3.4")
        assert result.status == ProviderStatus.NOT_FOUND
        assert result.data is None
        assert "no record" in result.error


# ---------------------------------------------------------------------------
# ZeroBounce parsing
# ---------------------------------------------------------------------------

class TestZeroBounceProvider:

    ZB_RESPONSE = {
        "address": "attacker@evil.com",
        "status": "do_not_mail",
        "sub_status": "toxic",
        "free_email": False,
        "catchall_domain": False,
        "did_you_mean": None,
        "domain": "evil.com",
        "domain_age_days": "12",
        "mx_found": "true",
        "mx_record": "mx.evil.com",
        "smtp_provider": None,
    }

    def test_lookup_email_success(self):
        p = ZeroBounceProvider("key")
        _patch_request(p, self.ZB_RESPONSE)
        result = p.lookup_email("attacker@evil.com")
        assert result.is_success()
        assert result.data["status"] == "do_not_mail"
        assert result.data["sub_status"] == "toxic"
        assert result.data["domain_age_days"] == 12

    def test_ip_not_supported(self):
        p = ZeroBounceProvider("key")
        result = p.lookup_ip("1.2.3.4")
        assert result.status == ProviderStatus.UNSUPPORTED


# ---------------------------------------------------------------------------
# HTTPS enforcement
# ---------------------------------------------------------------------------

class TestHTTPSEnforcement:

    def test_http_url_rejected(self):
        p = VirusTotalProvider("key")
        # Manually call _request with http URL
        result = p._request("GET", "http://insecure.example.com")
        assert result.status == ProviderStatus.ERROR
        assert "HTTPS" in (result.error or "")

    def test_provider_session_has_no_http_adapter(self):
        """Provider session'ı HTTP transport'u desteklememeli."""
        provider = VirusTotalProvider(api_key="dummy")
        try:
            adapters = provider._session.adapters
            # Session'da http:// için adapter olmamalı
            assert "http://" not in adapters or adapters.get("http://") is None
        finally:
            provider._session.close()

    def test_provider_rejects_http_url(self):
        """_request() metodu HTTP URL'leri reddetmeli."""
        provider = VirusTotalProvider(api_key="dummy")
        try:
            result = provider._request("GET", "http://evil.com/api")
            assert result.status == ProviderStatus.ERROR
            assert "HTTPS" in (result.error or "")
        finally:
            provider._session.close()
