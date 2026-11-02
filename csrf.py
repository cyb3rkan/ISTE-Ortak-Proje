"""
CSRF protection for cookie-authenticated endpoints (Phase 5a).

The refresh token lives in an httpOnly cookie, so it is automatically sent on
every same-site request — which is exactly what CSRF abuses. We defend with
the **double-submit cookie** pattern:

* On login we set a *non-httpOnly* CSRF cookie containing a random token.
* The browser JS reads that cookie and echoes it back in the
  ``X-CSRF-Token`` header on every state-changing ``/auth`` request.
* The server requires header == cookie. A cross-site attacker can trigger the
  cookie to be sent but cannot read it (same-origin policy) and therefore
  cannot set a matching header.

The comparison is constant-time. The CSRF token is **not** a secret in the
confidentiality sense — it is an unpredictability token — but we still avoid
logging it.
"""
from __future__ import annotations

import hmac
import secrets

_CSRF_TOKEN_BYTES = 32


def create_csrf_token() -> str:
    """Return a fresh, URL-safe, unpredictable CSRF token."""
    return secrets.token_urlsafe(_CSRF_TOKEN_BYTES)


def verify_csrf(cookie_value: str | None, header_value: str | None) -> bool:
    """
    Return ``True`` iff the CSRF cookie and ``X-CSRF-Token`` header match.

    Both must be present and non-empty. Comparison is constant-time.
    """
    if not cookie_value or not header_value:
        return False
    a = cookie_value.encode("utf-8", "strict")
    b = header_value.encode("utf-8", "strict")
    return hmac.compare_digest(a, b)
