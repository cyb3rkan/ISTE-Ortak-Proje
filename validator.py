"""
IOC validation and sanitisation.

All user input passes through this module before reaching any provider.
Invalid or unrecognised indicators are rejected early with a clear reason.

Usage:
    from ioc_enricher.core.validator import IOCValidator, sanitize_ioc

    clean = sanitize_ioc("hxxp://evil[.]com")   # → "http://evil.com"
    ioc, error = IOCValidator.validate(clean)    # returns IOC or raises
"""
from __future__ import annotations

import ipaddress
import re
import unicodedata
from typing import Optional, Tuple

from ..models.ioc import IOC, IOCType


# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------

_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,}$"
)
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
)
_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")

# Maximum lengths for basic sanity
_MAX_IOC_LEN = 2048
_MAX_DOMAIN_LEN = 253

# Control (C0/C1, incl. ESC and tab), invisible formatting (bidi overrides,
# zero-width, BOM), surrogates and line/paragraph separators. No IOC type
# legitimately contains them; in a URL they could rewrite a terminal or make
# the indicator read differently from what is sent to the providers.
_INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})


def _has_invisible_characters(value: str) -> bool:
    if value.isprintable():
        return False
    return any(unicodedata.category(ch) in _INVISIBLE_CATEGORIES for ch in value)


class IOCValidator:
    """
    Stateless validator that identifies and validates IOC strings.

    Detection order matters:
        1. IP address (v4 then v6)
        2. Hash (MD5 → SHA1 → SHA256)
        3. URL (before domain, since URLs contain domains)
        4. Email (before domain for the same reason)
        5. Domain
        6. Unknown → rejected
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @classmethod
    def validate(cls, raw: str) -> Tuple[Optional[IOC], Optional[str]]:
        """
        Validate and classify *raw* as an IOC.

        Args:
            raw: The indicator string (should already be sanitised).

        Returns:
            A ``(IOC, None)`` tuple on success, or ``(None, error_message)``
            on failure.
        """
        if not raw or not raw.strip():
            return None, "IOC value cannot be empty."

        value = raw.strip()

        if len(value) > _MAX_IOC_LEN:
            return None, f"IOC exceeds maximum length ({_MAX_IOC_LEN} chars)."

        # The value is not echoed: it is what makes the message unsafe.
        if _has_invisible_characters(value):
            return None, "IOC contains control or invisible formatting characters."

        ioc_type = cls._detect_type(value)
        if ioc_type == IOCType.UNKNOWN:
            return None, (
                f"'{value[:80]}' does not match any supported IOC type "
                f"(IPv4, IPv6, domain, URL, hash, email)."
            )

        return IOC(value=value, ioc_type=ioc_type), None

    @classmethod
    def identify(cls, raw: str) -> IOCType:
        """Detect the IOC type without full validation (convenience method)."""
        return cls._detect_type(raw.strip()) if raw else IOCType.UNKNOWN

    # ------------------------------------------------------------------
    # Individual type checkers (public for use in tests)
    # ------------------------------------------------------------------

    @staticmethod
    def is_ipv4(value: str) -> bool:
        try:
            ipaddress.IPv4Address(value)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_ipv6(value: str) -> bool:
        try:
            ipaddress.IPv6Address(value)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_md5(value: str) -> bool:
        return bool(_MD5_RE.fullmatch(value))

    @staticmethod
    def is_sha1(value: str) -> bool:
        return bool(_SHA1_RE.fullmatch(value))

    @staticmethod
    def is_sha256(value: str) -> bool:
        return bool(_SHA256_RE.fullmatch(value))

    @staticmethod
    def is_url(value: str) -> bool:
        return bool(_URL_RE.match(value))

    @staticmethod
    def is_email(value: str) -> bool:
        return bool(_EMAIL_RE.fullmatch(value))

    @staticmethod
    def is_domain(value: str) -> bool:
        if not value or len(value) > _MAX_DOMAIN_LEN:
            return False
        return bool(_DOMAIN_RE.fullmatch(value))

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @classmethod
    def _detect_type(cls, value: str) -> IOCType:
        if cls.is_ipv4(value):
            return IOCType.IPV4
        if cls.is_ipv6(value):
            return IOCType.IPV6
        if cls.is_md5(value):
            return IOCType.MD5
        if cls.is_sha1(value):
            return IOCType.SHA1
        if cls.is_sha256(value):
            return IOCType.SHA256
        if cls.is_url(value):
            return IOCType.URL
        if cls.is_email(value):
            return IOCType.EMAIL
        if cls.is_domain(value):
            return IOCType.DOMAIN
        return IOCType.UNKNOWN


# ---------------------------------------------------------------------------
# Sanitisation helper
# ---------------------------------------------------------------------------

# Matched in any letter case: reports write hXXp://, HXXPS://, [DOT], (At).
_DEFANG_PATTERNS = [
    (re.compile(r"hxxps://", re.IGNORECASE), "https://"),
    (re.compile(r"hxxp://", re.IGNORECASE), "http://"),
    (re.compile(r"\[\.\]|\[dot\]|\(dot\)", re.IGNORECASE), "."),
    (re.compile(r"\[@\]|\[at\]|\(at\)", re.IGNORECASE), "@"),
]


def sanitize_ioc(raw: str) -> str:
    """
    Refang a potentially defanged indicator.

    Common defanging patterns found in threat reports (any letter case):
        hxxp://evil[.]com  →  http://evil.com
        HXXPS://evil[DOT]com  →  https://evil.com
        192[.]168[.]1[.]1  →  192.168.1.1
        user[@]evil[.]com  →  user@evil.com

    Args:
        raw: Raw indicator string from user input or a text file.

    Returns:
        Sanitised string ready for validation.
    """
    value = raw.strip()
    for pattern, normal in _DEFANG_PATTERNS:
        value = pattern.sub(normal, value)
    return value
