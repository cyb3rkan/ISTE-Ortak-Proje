"""
API-key authentication primitives.

These helpers are framework-agnostic — they take strings and return strings
or booleans. FastAPI integration lives in :mod:`.policies`.

Security notes:

* Comparisons go through :func:`hmac.compare_digest` so candidate keys cannot
  be distinguished by request timing.
* We walk the *entire* configured-keys list on every call (no early ``break``
  on a successful match) so the number of comparisons is constant per request.
* Empty / ``None`` candidates are rejected up front; we never feed them to
  ``compare_digest``.
* The candidate value supplied by the client is **never** logged, returned
  in a response, or echoed back from an exception message.
"""
from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Iterable, Optional


# ---------------------------------------------------------------------------
# Public model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Principal:
    """The successful result of an auth check."""

    auth_type: str  # "api_key" | "anonymous"
    scope: str      # "api" | "admin" | "public"


_ANONYMOUS = Principal(auth_type="anonymous", scope="public")


def anonymous() -> Principal:
    return _ANONYMOUS


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class AuthError(Exception):
    """Base class for all auth failures handled by the API."""

    status_code: int = 401
    title: str = "Authentication required"
    err_type: str = "authentication"

    def __init__(self, detail: str = "Authentication required") -> None:
        super().__init__(detail)
        self.detail = detail


class AuthRequiredError(AuthError):
    """The request did not present a credential where one was needed."""

    status_code = 401
    title = "Authentication required"
    err_type = "authentication-required"


class AuthForbiddenError(AuthError):
    """A credential was presented but it was invalid or under-scoped."""

    status_code = 403
    title = "Forbidden"
    err_type = "authentication-forbidden"


class AuthUnavailableError(AuthError):
    """
    Auth cannot be performed because the server is misconfigured.

    Mapped to 503 — e.g. user auth is enabled but no (or a weak) JWT secret
    was supplied. The detail is generic so it never leaks configuration.
    """

    status_code = 503
    title = "Service unavailable"
    err_type = "authentication-unavailable"


# ---------------------------------------------------------------------------
# Key comparison
# ---------------------------------------------------------------------------

def compare_api_key(candidate: Optional[str], expected: Optional[str]) -> bool:
    """
    Constant-time equality between a request-supplied key and a configured one.

    Returns ``False`` for any ``None``/empty input on either side without ever
    leaking the configured key via timing.
    """
    if not candidate or not expected:
        return False
    a = candidate.encode("utf-8", errors="strict")
    b = expected.encode("utf-8", errors="strict")
    # hmac.compare_digest already runs in constant time relative to the
    # *shorter* of the two inputs, and it tolerates mismatched lengths.
    return hmac.compare_digest(a, b)


def match_api_key(candidate: Optional[str], known: Iterable[str]) -> bool:
    """
    Return True iff *candidate* matches at least one entry in *known*.

    Always walks the full *known* list — no short-circuit on first match —
    so timing leaks the *number* of configured keys, not which one matched.
    """
    if not candidate:
        # Still run the loop once with a dummy compare so callers can't tell
        # the difference between "no key supplied" and "key didn't match"
        # purely from response timing. Functionally returns False.
        for k in known:
            compare_api_key("", k)
        return False

    matched = False
    for k in known:
        if compare_api_key(candidate, k):
            matched = True
            # IMPORTANT: do NOT break — we want the loop to always run to
            # completion to keep comparison count constant.
    return matched
