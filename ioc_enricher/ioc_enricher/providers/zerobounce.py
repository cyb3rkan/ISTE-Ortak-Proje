"""
ZeroBounce email validation provider.

ZeroBounce classifies an address by deliverability and list hygiene: a
``status`` (valid, invalid, catch-all, unknown, spamtrap, abuse, do_not_mail)
refined by a ``sub_status`` (e.g. toxic, disposable, role_based), plus the
age of the email domain. Only the risk-relevant, non-personal fields are kept:
the owner's name, gender and geo-location are never stored.

Supported IOC types: email
Docs: https://www.zerobounce.net/docs/email-validation-api-quickstart/v2-validate-emails
"""
from __future__ import annotations

from typing import Any, Dict, FrozenSet, Optional

from ..models import IOCType, ProviderResult, ProviderStatus
from ..utils.logger import get_logger
from ._fields import flag, text
from .base import BaseProvider

log = get_logger(__name__)

#: Documented ``status`` values; anything else breaks the contract.
STATUSES: FrozenSet[str] = frozenset({
    "valid", "invalid", "catch-all", "unknown", "spamtrap", "abuse", "do_not_mail",
})


def _text_flag(value: Any) -> Optional[bool]:
    """A boolean sent as a JSON boolean or as the documented "true"/"false"."""
    if isinstance(value, bool):
        return value
    if value == "true":
        return True
    if value == "false":
        return False
    return None


def _days(value: Any) -> Optional[int]:
    """A non-negative day count sent as an integer or a digit string."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


class ZeroBounceProvider(BaseProvider):
    """ZeroBounce email validation provider."""

    BASE_URL = "https://api.zerobounce.net/v2/validate"

    SUPPORTED_IOC_TYPES: FrozenSet[IOCType] = frozenset([IOCType.EMAIL])

    @property
    def name(self) -> str:
        return "ZeroBounce"

    def _get_headers(self) -> Dict[str, str]:
        # The key is a form field (see lookup_email), never a header or URL part.
        return {
            "Accept": "application/json",
            "User-Agent": "ioc-enricher/2.0",
        }

    def lookup_email(self, email: str) -> ProviderResult:
        """Validate *email* with ZeroBounce."""
        # POST form body: the key and the address stay out of the URL, and an
        # address containing '&' or '?' cannot add or alter request fields.
        result = self._request(
            "POST", self.BASE_URL,
            form_body={"api_key": self._api_key, "email": email},
        )

        if not result.is_success():
            return result

        raw = result.data
        if "error" in raw:
            return self._key_rejected(result)

        status = (text(raw.get("status"), 32) or "").lower()
        if status not in STATUSES:
            # Without a documented verdict nothing can be judged, so the
            # answer must not read as "nothing suspicious".
            return self._invalid(result, "no documented status")

        result.data = {
            "email": email,
            "status": status,
            "sub_status": (text(raw.get("sub_status"), 32) or "").lower(),
            "free_email": flag(raw.get("free_email")),
            "catchall_domain": flag(raw.get("catchall_domain")),
            "mx_found": _text_flag(raw.get("mx_found")),
            "mx_record": text(raw.get("mx_record"), 255),
            "smtp_provider": text(raw.get("smtp_provider"), 64),
            "did_you_mean": text(raw.get("did_you_mean"), 320),
            "domain": text(raw.get("domain"), 255),
            "domain_age_days": _days(raw.get("domain_age_days")),
            "processed_at": text(raw.get("processed_at"), 32),
        }
        return result

    def _key_rejected(self, result: ProviderResult) -> ProviderResult:
        """
        ZeroBounce answers a bad key or an empty credit balance with HTTP 200
        and an ``error`` field. Treat it like a 401: every address would get
        the same answer, and repeated bad-key calls get the key blocked for an
        hour, so the provider pauses. The provider's text is not echoed.
        """
        self._auth_rejected_until = self._clock() + self.AUTH_RETRY_SECONDS
        log.warning(
            "%s rejected the API key or has no credits; not queried again for %.0fs.",
            self.name, self.AUTH_RETRY_SECONDS,
        )
        result.status = ProviderStatus.ERROR
        result.data = None
        result.error = (
            f"{self.name} rejected the API key or the account has no credits; "
            f"not queried again for {self.AUTH_RETRY_SECONDS:.0f}s."
        )
        return result
