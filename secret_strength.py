"""
One strength bar for every shared secret the web API is configured with —
the JWT signing secret and the API keys.

* A documented placeholder or a well-known weak value is public knowledge:
  it is refused in every mode, debug included.
* Otherwise a secret must look generated: at least 32 characters, at least 8
  distinct characters, no repeated block, not mostly an alphabet, digit or
  keyboard run. ``secrets.token_urlsafe(32)`` (43 characters) and
  ``secrets.token_hex(32)`` (64) pass by a wide margin.

Nothing here logs or returns a secret value.
"""
from __future__ import annotations

import re
from typing import Iterable, List, Optional

from ...settings import WebSettings

# Minimum acceptable secret length when strong-secret enforcement is on.
_MIN_STRONG_SECRET_LEN = 32
# A random secret of that length uses far more distinct characters than this;
# fewer means a repeated value (sequences are caught by _is_sequential).
_MIN_DISTINCT_SECRET_CHARS = 8

# Obviously-weak placeholder secrets that must never reach production.
_WEAK_SECRET_DENYLIST = frozenset(
    {
        "changeme",
        "change-me",
        "secret",
        "jwt-secret",
        "dev",
        "development",
        "test",
        "please-change-me",
    }
)

# Words that only show up in documentation placeholders and examples
# (``REPLACE_WITH_...``, ``change-me``, ``your-secret-here``). They are matched
# case-insensitively with non-alphanumerics removed. Every marker has 5+
# letters including a non-hex one, so a generated secret practically never
# contains one by chance (a hex secret never can).
_PLACEHOLDER_MARKERS = (
    "replace", "change", "placeholder", "example", "sample", "dummy",
    "default", "insert", "secret", "password", "strong", "random", "generate",
)

# What people type when asked for something random: alphabet and digit runs
# and keyboard rows, in either direction. Neighbouring characters of a
# generated secret fall on these by chance only rarely (about 12% for hex,
# 9% for base64url), far below the "more than half" that _is_sequential needs.
_SEQUENCE_ROWS = (
    "abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop", "asdfghjkl", "zxcvbnm",
)
_SEQUENCE_NEIGHBOURS = frozenset(
    pair
    for row in _SEQUENCE_ROWS
    for a, b in zip(row, row[1:])
    for pair in ((a, b), (b, a))
)


def is_public_secret(secret: str) -> bool:
    """
    True for documented placeholders and well-known weak values.

    These are public knowledge, so they are refused in every mode.
    """
    if secret.strip().lower() in _WEAK_SECRET_DENYLIST:
        return True
    normalized = re.sub(r"[^a-z0-9]", "", secret.lower())
    return any(marker in normalized for marker in _PLACEHOLDER_MARKERS)


def _is_repetitive(secret: str) -> bool:
    """True when *secret* has too few distinct characters or repeats a block."""
    if len(set(secret)) < _MIN_DISTINCT_SECRET_CHARS:
        return True
    return any(
        secret[size:] == secret[:-size] for size in range(1, len(secret) // 2 + 1)
    )


def _is_sequential(secret: str) -> bool:
    """True when most neighbouring characters follow a sequence row."""
    lowered = secret.lower()
    pairs = list(zip(lowered, lowered[1:]))
    in_sequence = sum(1 for pair in pairs if pair in _SEQUENCE_NEIGHBOURS)
    return in_sequence * 2 > len(pairs)


def is_strong_secret(secret: Optional[str]) -> bool:
    """Return ``True`` iff *secret* meets the strong-secret bar."""
    if not secret:
        return False
    if len(secret) < _MIN_STRONG_SECRET_LEN:
        return False
    if is_public_secret(secret) or _is_repetitive(secret) or _is_sequential(secret):
        return False
    return True


# ---------------------------------------------------------------------------
# API keys
# ---------------------------------------------------------------------------

def api_key_problem(key: str, settings: WebSettings) -> Optional[str]:
    """
    ``"placeholder"`` or ``"weak"`` for a configured API key that must not be
    accepted, else ``None``.

    Same policy as the JWT secret: placeholders are refused in every mode;
    other weak keys in debug mode and — unless
    ``require_strong_api_keys_in_prod`` is switched off — in production.
    """
    if is_public_secret(key):
        return "placeholder"
    enforce_strength = settings.debug or settings.require_strong_api_keys_in_prod
    if enforce_strength and not is_strong_secret(key):
        return "weak"
    return None


def accepted_api_keys(keys: Iterable[str], settings: WebSettings) -> List[str]:
    """The configured keys a request may authenticate with (fail closed)."""
    return [key for key in keys if api_key_problem(key, settings) is None]
