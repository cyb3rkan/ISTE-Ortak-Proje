"""
AbuseIPDB v2 API provider.

Supported IOC types: IPv4, IPv6
Docs: https://docs.abuseipdb.com/
"""
from __future__ import annotations

from typing import Any, Dict, FrozenSet, List

from ..models import IOCType, ProviderResult
from ._fields import InvalidResponse, count, flag, required_count, text, text_list
from .base import BaseProvider

# Report category ids: https://www.abuseipdb.com/categories lists 1-23; the
# bound leaves room for categories AbuseIPDB adds later.
_MAX_CATEGORY = 255


def _categories(value: Any) -> List[int]:
    """The valid category ids of one report, in their original order."""
    if not isinstance(value, list):
        return []
    return [c for c in (count(v, _MAX_CATEGORY) for v in value) if c]


class AbuseIPDBProvider(BaseProvider):
    """AbuseIPDB IP reputation provider."""

    BASE_URL = "https://api.abuseipdb.com/api/v2"

    SUPPORTED_IOC_TYPES: FrozenSet[IOCType] = frozenset(
        [IOCType.IPV4, IOCType.IPV6]
    )

    @property
    def name(self) -> str:
        return "AbuseIPDB"

    def _get_headers(self) -> Dict[str, str]:
        return {
            "Key": self._api_key,
            "Accept": "application/json",
        }

    def lookup_ip(self, ip: str) -> ProviderResult:
        """Check IP reputation and abuse reports."""
        result = self._request(
            "GET",
            f"{self.BASE_URL}/check",
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
        )

        if not result.is_success():
            return result

        raw = result.data.get("data")
        if not isinstance(raw, dict):
            return self._invalid(result, "no data object")
        try:
            # The evidence the scorer reads must be there with its type; a
            # missing score is a broken answer, not a score of 0.
            score = required_count(raw.get("abuseConfidenceScore"), "abuseConfidenceScore", 100)
            total_reports = required_count(raw.get("totalReports"), "totalReports")
        except InvalidResponse as exc:
            return self._invalid(result, str(exc))

        reports_raw = raw.get("reports")
        reports = (
            [r for r in reports_raw if isinstance(r, dict)]
            if isinstance(reports_raw, list) else []
        )
        recent_reports = [
            {
                "reported_at": text(r.get("reportedAt"), 64),
                # Truncate to avoid storing excessive data
                "comment": text(r.get("comment"), 200) or "",
                "categories": _categories(r.get("categories")),
                "reporter_country": text(r.get("reporterCountryCode"), 8),
            }
            for r in reports[:5]
        ]

        result.data = {
            "ip": ip,
            "abuse_confidence_score": score,
            # Documented as null when no whitelist lookup was performed.
            "is_whitelisted": flag(raw.get("isWhitelisted")),
            "is_tor": flag(raw.get("isTor")),
            "is_public": flag(raw.get("isPublic")),
            "country_code": text(raw.get("countryCode"), 8),
            "country_name": text(raw.get("countryName"), 64),
            "isp": text(raw.get("isp")),
            "domain": text(raw.get("domain")),
            "usage_type": text(raw.get("usageType"), 64),
            "total_reports": total_reports,
            "num_distinct_users": count(raw.get("numDistinctUsers")),
            "last_reported_at": text(raw.get("lastReportedAt"), 64),
            "hostnames": text_list(raw.get("hostnames")),
            # Distinct category ids across every returned report; the
            # recent_reports sample above keeps only five of them.
            "categories": sorted(
                {c for r in reports for c in _categories(r.get("categories"))}
            ),
            "recent_reports": recent_reports,
        }
        return result
