"""
AlienVault OTX (Open Threat Exchange) API provider.

Supported IOC types: IPv4, IPv6, domain, URL, MD5, SHA1, SHA256
Docs: https://otx.alienvault.com/api
"""
from __future__ import annotations

import urllib.parse
from typing import Any, Dict, FrozenSet, List, Tuple

from ..models import IOCType, ProviderResult
from ._fields import InvalidResponse, integer, required_count, text
from .base import BaseProvider


def _pulse_info(raw: Dict[str, Any]) -> Tuple[int, List[Dict[str, Any]]]:
    """
    ``(pulse count, pulses)`` from a ``general`` section answer.

    The count is the evidence: when it is missing the answer is invalid, not
    "0 pulses".
    """
    info = raw.get("pulse_info")
    if not isinstance(info, dict):
        raise InvalidResponse("no pulse_info object")
    pulse_count = required_count(info.get("count"), "pulse_info.count")
    pulses = info.get("pulses")
    return pulse_count, (
        [p for p in pulses if isinstance(p, dict)] if isinstance(pulses, list) else []
    )


class OTXProvider(BaseProvider):
    """AlienVault OTX community threat intelligence provider."""

    BASE_URL = "https://otx.alienvault.com/api/v1"

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
        return "AlienVault OTX"

    def _get_headers(self) -> Dict[str, str]:
        return {"X-OTX-API-KEY": self._api_key, "Accept": "application/json"}

    # ------------------------------------------------------------------
    # Lookups
    # ------------------------------------------------------------------

    def lookup_ip(self, ip: str) -> ProviderResult:
        # OTX files IPv4 and IPv6 indicators under separate sections.
        section = "IPv6" if ":" in ip else "IPv4"
        result = self._request("GET", f"{self.BASE_URL}/indicators/{section}/{ip}/general")
        if not result.is_success():
            return result
        return self._parse_ip_domain(result, "ip", ip, section)

    def lookup_domain(self, domain: str) -> ProviderResult:
        result = self._request(
            "GET", f"{self.BASE_URL}/indicators/domain/{domain}/general"
        )
        if not result.is_success():
            return result
        return self._parse_ip_domain(result, "domain", domain, "domain")

    def lookup_hash(self, file_hash: str) -> ProviderResult:
        result = self._request(
            "GET", f"{self.BASE_URL}/indicators/file/{file_hash}/general"
        )
        if not result.is_success():
            return result
        raw = result.data
        try:
            pulse_count, _ = _pulse_info(raw)
        except InvalidResponse as exc:
            return self._invalid(result, str(exc))
        result.data = {
            "hash": file_hash,
            "pulse_count": pulse_count,
            "file_type": text(raw.get("file_type"), 64),
            "file_class": text(raw.get("file_class"), 64),
        }
        return result

    def lookup_url(self, url: str) -> ProviderResult:
        encoded = urllib.parse.quote(url, safe="")
        result = self._request(
            "GET", f"{self.BASE_URL}/indicators/url/{encoded}/general"
        )
        if not result.is_success():
            return result
        raw = result.data
        try:
            pulse_count, _ = _pulse_info(raw)
        except InvalidResponse as exc:
            return self._invalid(result, str(exc))
        result.data = {
            "url": url,
            "pulse_count": pulse_count,
            "domain": text(raw.get("domain")),
            "alexa": text(raw.get("alexa")),
        }
        return result

    # ------------------------------------------------------------------
    # Shared parser
    # ------------------------------------------------------------------

    def _parse_ip_domain(
        self,
        result: ProviderResult,
        key: str,
        value: str,
        indicator_type: str,
    ) -> ProviderResult:
        raw = result.data
        try:
            pulse_count, pulses = _pulse_info(raw)
        except InvalidResponse as exc:
            return self._invalid(result, str(exc))
        result.data = {
            key: value,
            "pulse_count": pulse_count,
            "pulse_references": [
                {"name": text(p.get("name")), "author": text(p.get("author_name"), 64)}
                for p in pulses[:5]
            ],
            "reputation": integer(raw.get("reputation")),
            "country_code": text(raw.get("country_code"), 8),
            "country_name": text(raw.get("country_name"), 64),
            "asn": text(raw.get("asn"), 128),
            "city": text(raw.get("city"), 64),
            "whois": text(raw.get("whois")),
            "alexa": text(raw.get("alexa")),
        }
        return result
