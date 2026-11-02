"""
Shodan API provider.

Supported IOC types: IPv4, IPv6, domain
Docs: https://developer.shodan.io/api
"""
from __future__ import annotations

from typing import Any, Dict, FrozenSet, List

from ..models import IOCType, ProviderResult, ProviderStatus
from ._fields import count, text, text_list
from .base import BaseProvider


def _cve_ids(value: Any) -> List[str]:
    """CVE ids from ``vulns``: a list of ids, or an object keyed by id."""
    if isinstance(value, dict):
        value = list(value)
    return text_list(value, 100, 32)


class ShodanProvider(BaseProvider):
    """Shodan internet-of-things search engine provider."""

    BASE_URL = "https://api.shodan.io"

    SUPPORTED_IOC_TYPES: FrozenSet[IOCType] = frozenset(
        [IOCType.IPV4, IOCType.IPV6, IOCType.DOMAIN]
    )

    @property
    def name(self) -> str:
        return "Shodan"

    def _get_headers(self) -> Dict[str, str]:
        # Shodan passes its key as a query parameter, not a header
        return {"Accept": "application/json"}

    def lookup_ip(self, ip: str) -> ProviderResult:
        """Retrieve host information from Shodan."""
        result = self._request(
            "GET",
            f"{self.BASE_URL}/shodan/host/{ip}",
            params={"key": self._api_key},
        )

        if result.status == ProviderStatus.NOT_FOUND:
            result.error = "IP address not found in Shodan database."
            return result

        if not result.is_success():
            return result

        raw = result.data
        ports = raw.get("ports")
        if not isinstance(ports, list):
            return self._invalid(result, "ports is not a list")

        banners = raw.get("data")
        services: List[dict] = [
            {
                "port": count(svc.get("port"), 65535),
                "transport": text(svc.get("transport"), 16),
                "product": text(svc.get("product")),
                "version": text(svc.get("version"), 64),
                # Limit banner length to avoid massive payloads
                "banner": text(svc.get("data"), 300) or "",
            }
            for svc in (banners if isinstance(banners, list) else [])
            if isinstance(svc, dict)
        ]

        result.data = {
            "ip": ip,
            "hostnames": text_list(raw.get("hostnames")),
            "domains": text_list(raw.get("domains")),
            "country_code": text(raw.get("country_code"), 8),
            "country_name": text(raw.get("country_name"), 64),
            "city": text(raw.get("city"), 64),
            "isp": text(raw.get("isp")),
            "asn": text(raw.get("asn"), 32),
            "organization": text(raw.get("org")),
            "os": text(raw.get("os"), 64),
            "ports": sorted({p for p in (count(v, 65535) for v in ports) if p is not None}),
            "services": services,
            "tags": text_list(raw.get("tags")),
            # CVE IDs associated with this host
            "vulns": _cve_ids(raw.get("vulns")),
            "last_update": text(raw.get("last_update"), 32),
        }
        return result

    def lookup_domain(self, domain: str) -> ProviderResult:
        """Resolve domain → IP via Shodan DNS, then return IP data."""
        result = self._request(
            "GET",
            f"{self.BASE_URL}/dns/resolve",
            params={"hostnames": domain, "key": self._api_key},
        )

        if not result.is_success():
            return result

        ip_address = result.data.get(domain)
        if ip_address is None or ip_address == "":
            result.status = ProviderStatus.NOT_FOUND
            result.error = "Domain could not be resolved by Shodan."
            result.data = None
            return result
        if not isinstance(ip_address, str):
            return self._invalid(result, "the resolved address is not a string")

        result.data = {"domain": domain, "resolved_ip": ip_address[:64]}
        return result
