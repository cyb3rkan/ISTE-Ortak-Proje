"""
VirusTotal v3 API provider.

Supported IOC types: IPv4, IPv6, domain, URL, MD5, SHA1, SHA256
Docs: https://developers.virustotal.com/reference/overview
"""
from __future__ import annotations

import base64
from typing import Any, Dict, FrozenSet, Tuple

from ..models import IOCType, ProviderResult, ProviderStatus
from ._fields import InvalidResponse, count, integer, required_count, text, text_list
from .base import BaseProvider

# ``last_analysis_stats`` keys (VirusTotal analyses object). A verdict: the
# engine analysed the object and answered ("undetected" = found nothing).
_VERDICT_KEYS = ("malicious", "suspicious", "harmless", "undetected")
# No result: the engine timed out, failed, or does not support the file type.
_NO_RESULT_KEYS = ("timeout", "confirmed-timeout", "failure", "type-unsupported")


class VirusTotalProvider(BaseProvider):
    """VirusTotal threat intelligence provider."""

    BASE_URL = "https://www.virustotal.com/api/v3"

    SUPPORTED_IOC_TYPES: FrozenSet[IOCType] = frozenset(
        [
            IOCType.IPV4, IOCType.IPV6,
            IOCType.DOMAIN,
            IOCType.URL,
            IOCType.MD5, IOCType.SHA1, IOCType.SHA256,
        ]
    )

    @property
    def name(self) -> str:
        return "VirusTotal"

    def _get_headers(self) -> Dict[str, str]:
        return {"x-apikey": self._api_key, "Accept": "application/json"}

    # ------------------------------------------------------------------
    # Lookup methods
    # ------------------------------------------------------------------

    def lookup_ip(self, ip: str) -> ProviderResult:
        """Query VirusTotal for an IP address."""
        result = self._request("GET", f"{self.BASE_URL}/ip_addresses/{ip}")
        return self._parse_standard(result, "ip", ip)

    def lookup_domain(self, domain: str) -> ProviderResult:
        """Query VirusTotal for a domain."""
        result = self._request("GET", f"{self.BASE_URL}/domains/{domain}")
        return self._parse_standard(result, "domain", domain)

    def lookup_hash(self, file_hash: str) -> ProviderResult:
        """Query VirusTotal for a file hash (MD5 / SHA1 / SHA256)."""
        result = self._request("GET", f"{self.BASE_URL}/files/{file_hash}")
        if result.status == ProviderStatus.NOT_FOUND:
            result.error = "File hash not found in VirusTotal database."
        return self._parse_standard(result, "hash", file_hash)

    def lookup_url(self, url: str) -> ProviderResult:
        """
        Query VirusTotal for a URL.

        VirusTotal requires the URL to be base64url-encoded (no padding).
        """
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        result = self._request("GET", f"{self.BASE_URL}/urls/{url_id}")
        return self._parse_standard(result, "url", url)

    # ------------------------------------------------------------------
    # Shared parser
    # ------------------------------------------------------------------

    def _parse_standard(
        self, result: ProviderResult, ioc_key: str, ioc_value: str
    ) -> ProviderResult:
        """
        Extract the normalised fields common to all VirusTotal responses.

        The raw API response always has the structure:
            { "data": { "attributes": { "last_analysis_stats": {...} } } }

        ``total_engines`` counts only engines that returned a verdict
        (malicious + suspicious + harmless + undetected): the denominator of
        the detection ratio. Engines that timed out, failed or do not support
        the file type are ``no_result_engines`` — neither clean nor malicious.
        An object no engine has a verdict on (queued, never analysed, or every
        engine without a result) is NOT_FOUND: no evidence, never "0/N".
        """
        if not result.is_success():
            return result

        try:
            attributes, stats = self._analysis(result.data)
        except InvalidResponse as exc:
            return self._invalid(result, str(exc))

        total = sum(stats[key] for key in _VERDICT_KEYS)
        no_result = sum(stats[key] for key in _NO_RESULT_KEYS)
        if total == 0:
            result.status = ProviderStatus.NOT_FOUND
            result.data = None
            result.error = "VirusTotal has no completed analysis for this IOC" + (
                f" ({no_result} engine(s) returned no result)." if no_result else "."
            )
            return result

        # URL-specific HTTP fields. last_http_response_* exists only on
        # URL lookups; we surface a compact ``status`` int and ``content_type``
        # so the UI can mirror the VirusTotal web verdict block.
        last_http_headers = attributes.get("last_http_response_headers")
        content_type = None
        if isinstance(last_http_headers, dict):
            # VT lower-cases keys but be defensive against case drift.
            for key, value in last_http_headers.items():
                if isinstance(key, str) and key.lower() == "content-type":
                    content_type = text(value, 128)
                    break

        raw_categories = attributes.get("categories")
        categories: Dict[str, str] = {}
        if isinstance(raw_categories, dict):
            for vendor, label in list(raw_categories.items())[:50]:
                if isinstance(vendor, str) and isinstance(label, str):
                    categories[vendor[:64]] = label[:128]

        result.data = {
            ioc_key: ioc_value,
            "malicious_count": stats["malicious"],
            "suspicious_count": stats["suspicious"],
            "harmless_count": stats["harmless"],
            "undetected_count": stats["undetected"],
            "total_engines": total,
            "no_result_engines": no_result,
            "reputation": integer(attributes.get("reputation")),
            "last_analysis_date": count(attributes.get("last_analysis_date"), 2**40),
            # Extra fields (None when absent for this IOC type or mistyped)
            "country": text(attributes.get("country"), 8),
            "asn": count(attributes.get("asn"), 2**32),
            "as_owner": text(attributes.get("as_owner")),
            "registrar": text(attributes.get("registrar")),
            "file_type": text(attributes.get("type_description")),
            "file_size": count(attributes.get("size"), 2**50),
            "md5": text(attributes.get("md5"), 32),
            "sha1": text(attributes.get("sha1"), 40),
            "sha256": text(attributes.get("sha256"), 64),
            "categories": categories,
            # URL-only extras (None for non-URL IOCs)
            "status": count(attributes.get("last_http_response_code"), 999),
            "content_type": content_type,
            "tags": text_list(attributes.get("tags"), 20, 64),
            "title": text(attributes.get("title")),
        }
        return result

    @staticmethod
    def _analysis(body: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, int]]:
        """Return ``(attributes, stats)``; every known stats key as a count."""
        data = body.get("data")
        attributes = data.get("attributes") if isinstance(data, dict) else None
        if not isinstance(attributes, dict):
            raise InvalidResponse("no data.attributes object")
        raw_stats = attributes.get("last_analysis_stats")
        if raw_stats is None:
            raw_stats = {}
        if not isinstance(raw_stats, dict):
            raise InvalidResponse("last_analysis_stats is not an object")
        stats = {
            key: required_count(raw_stats.get(key, 0), f"last_analysis_stats.{key}")
            for key in _VERDICT_KEYS + _NO_RESULT_KEYS
        }
        return attributes, stats
