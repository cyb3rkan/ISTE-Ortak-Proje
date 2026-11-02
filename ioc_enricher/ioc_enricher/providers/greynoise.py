"""
GreyNoise API provider.

GreyNoise classifies internet background noise and helps analysts
distinguish targeted attacks from mass internet scanners.

Endpoints (https://docs.greynoise.io):
    * IP Lookup      ``GET /v3/ip/{ip}`` — Internet Scanner Intelligence
      (formerly "noise") and Business Service Intelligence (formerly
      "RIOT") in one answer.
    * Community API  ``GET /v3/community/{ip}`` — fallback for keys without
      IP Lookup access; IPv4 only.

A 404, or ``found: false`` in both datasets, means GreyNoise has no record of
the IP: not observed scanning and not a known business service. That is no
evidence either way, so it is NOT_FOUND, never a verdict.

Supported IOC types: IPv4, IPv6 (the Community fallback: IPv4 only)
Docs: https://docs.greynoise.io/
"""
from __future__ import annotations

import ipaddress
from typing import Any, Dict, FrozenSet, Optional

from ..models import IOCType, ProviderResult, ProviderStatus
from ._fields import flag, text, text_list
from .base import BaseProvider

# Documented classifications; anything else is reported as "unknown".
_CLASSIFICATIONS = frozenset({"benign", "malicious", "suspicious", "unknown"})

_NO_RECORD = (
    "GreyNoise has no record of this IP: not observed scanning the internet "
    "and not a known business service."
)

_NO_IP_LOOKUP_FOR_IPV6 = (
    "GreyNoise IP Lookup is not available for this API key (HTTP 403); "
    "the Community API accepts IPv4 only."
)


def _classification(value: Any) -> str:
    label = value.strip().lower() if isinstance(value, str) else ""
    return label if label in _CLASSIFICATIONS else "unknown"


def _found(block: Any) -> Optional[bool]:
    """
    A dataset's ``found`` flag. A dataset left out of the answer was not
    found; ``None`` when the block or its flag has the wrong type.
    """
    if block is None:
        return False
    if not isinstance(block, dict):
        return None
    return flag(block.get("found"))


def _is_ipv4(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).version == 4
    except ValueError:
        return False


class GreyNoiseProvider(BaseProvider):
    """GreyNoise internet-noise classification provider."""

    IP_LOOKUP_URL = "https://api.greynoise.io/v3/ip"
    COMMUNITY_URL = "https://api.greynoise.io/v3/community"

    SUPPORTED_IOC_TYPES: FrozenSet[IOCType] = frozenset(
        [IOCType.IPV4, IOCType.IPV6]
    )

    #: After IP Lookup answers 403 (no IP Lookup access for this key or
    #: plan), lookups go straight to the Community API for this long.
    IP_LOOKUP_RETRY_SECONDS: float = 3600.0
    _ip_lookup_denied_until: float = 0.0

    @property
    def name(self) -> str:
        return "GreyNoise"

    def _get_headers(self) -> Dict[str, str]:
        return {
            "key": self._api_key,
            "Accept": "application/json",
        }

    def lookup_ip(self, ip: str) -> ProviderResult:
        """
        Query GreyNoise for IP context.

        Uses IP Lookup. A 403 there means the key or plan has no IP Lookup
        access: the same IPv4 lookup is retried once on the Community API,
        and later lookups go straight there for IP_LOOKUP_RETRY_SECONDS. A
        401 means the key itself was rejected, which the Community API would
        reject too, so it gets no fallback. Every HTTP request takes its own
        rate-limit token.
        """
        if self._clock() < self._ip_lookup_denied_until:
            if not _is_ipv4(ip):
                return ProviderResult(
                    provider=self.name,
                    status=ProviderStatus.ERROR,
                    error=_NO_IP_LOOKUP_FOR_IPV6,
                )
            result = self._request("GET", f"{self.COMMUNITY_URL}/{ip}")
        else:
            result = self._request("GET", f"{self.IP_LOOKUP_URL}/{ip}")
            if result.error == "HTTP 403":
                self._ip_lookup_denied_until = self._clock() + self.IP_LOOKUP_RETRY_SECONDS
                if _is_ipv4(ip):
                    result = self._request("GET", f"{self.COMMUNITY_URL}/{ip}")

        if result.status == ProviderStatus.NOT_FOUND:
            return self._no_record(result)
        if not result.is_success():
            return result

        raw = result.data
        if isinstance(raw.get("internet_scanner_intelligence"), dict) or isinstance(
            raw.get("business_service_intelligence"), dict
        ):
            return self._parse_ip_lookup(result, ip)
        return self._parse_community(result, ip)

    # ------------------------------------------------------------------
    # Parsers
    # ------------------------------------------------------------------

    def _parse_ip_lookup(self, result: ProviderResult, ip: str) -> ProviderResult:
        """IP Lookup answer (IPResponseV3)."""
        raw = result.data
        scanner = raw.get("internet_scanner_intelligence")
        business = raw.get("business_service_intelligence")
        noise, riot = _found(scanner), _found(business)
        if noise is None or riot is None:
            return self._invalid(result, "a dataset 'found' flag is not a boolean")
        if not noise and not riot:
            return self._no_record(result)

        scanner = scanner if isinstance(scanner, dict) else {}
        business = business if isinstance(business, dict) else {}
        metadata = scanner.get("metadata")
        metadata = metadata if isinstance(metadata, dict) else {}
        raw_tags = scanner.get("tags")
        tag_names = (
            [tag.get("name") for tag in raw_tags if isinstance(tag, dict)]
            if isinstance(raw_tags, list) else []
        )

        result.data = {
            "ip": ip,
            "noise": noise,
            "riot": riot,
            "classification": _classification(scanner.get("classification")),
            # As in the Community API: the business service's name, or the
            # scanner's actor.
            "name": text(business.get("name")) if riot else text(scanner.get("actor")),
            "last_seen": text(scanner.get("last_seen"), 32),
            "first_seen": text(scanner.get("first_seen"), 32),
            "actor": text(scanner.get("actor")),
            "tags": text_list(tag_names, 20, 64),
            "category": text(metadata.get("category"), 64),
            "country_code": text(metadata.get("source_country_code"), 8),
            "organization": text(metadata.get("organization")),
            "asn": text(metadata.get("asn"), 32),
            "tor": flag(scanner.get("tor")),
            "vpn": flag(scanner.get("vpn")),
            "data_source": "ip_lookup",
        }
        return result

    def _parse_community(self, result: ProviderResult, ip: str) -> ProviderResult:
        """Community API answer (flat noise / riot / classification)."""
        raw = result.data
        noise, riot = flag(raw.get("noise")), flag(raw.get("riot"))
        if noise is None or riot is None:
            return self._invalid(result, "'noise' or 'riot' is not a boolean")
        if not noise and not riot:
            return self._no_record(result)

        result.data = {
            "ip": ip,
            "noise": noise,
            "riot": riot,
            # GreyNoise's own label only: being seen scanning is not malicious.
            "classification": _classification(raw.get("classification")),
            "name": text(raw.get("name")),
            "link": text(raw.get("link")),
            "last_seen": text(raw.get("last_seen"), 32),
            "message": text(raw.get("message")),
            "data_source": "community",
        }
        return result

    @staticmethod
    def _no_record(result: ProviderResult) -> ProviderResult:
        result.status = ProviderStatus.NOT_FOUND
        result.data = None
        result.error = _NO_RECORD
        return result
