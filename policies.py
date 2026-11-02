"""
FastAPI dependencies implementing the API-key auth policy.

Policy summary:

* ``settings.auth_enabled is False``  → ``require_api_key`` fails closed
  with :class:`AuthUnavailableError` (503) and ``require_admin_api_key``
  with :class:`AuthForbiddenError` (403). The only exception is the
  development bypass (:func:`dev_auth_bypass_active`), which lets
  ``require_api_key`` return the anonymous principal; admin stays closed.
* ``settings.auth_enabled is True``   → ``require_api_key`` and
  ``require_admin_api_key`` raise :class:`AuthRequiredError` (401) when no
  credential is presented, and :class:`AuthForbiddenError` (403) when the
  credential is invalid or under-scoped.
* If ``auth_enabled is True`` but ``admin_api_keys`` is empty, admin
  endpoints fail closed with 403 + a clear "admin operations are not
  configured" detail.

Nothing here ever logs or returns the candidate key value.
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import Depends, Request

from ...settings import WebSettings
from ..deps import get_settings
from .auth import (
    AuthForbiddenError,
    AuthRequiredError,
    AuthUnavailableError,
    Principal,
    anonymous,
    match_api_key,
)
from .secret_strength import (
    accepted_api_keys,
)

log = logging.getLogger("ioc_enricher.web.auth")


def dev_auth_bypass_active(settings: WebSettings) -> bool:
    """
    True only for the explicit local-development bypass: no auth mode is
    enabled, ``IOC_WEB_DEV_ALLOW_UNAUTHENTICATED`` is on and the app runs in
    debug mode. It opens the non-admin routes only; admin routes stay closed.
    """
    return (
        settings.dev_allow_unauthenticated
        and settings.debug
        and not settings.auth_enabled
        and not settings.user_auth_enabled
    )


def _extract_header(request: Request, header_name: str) -> Optional[str]:
    """
    Pull a header value safely.

    We do **not** log either the header name's value or any client-supplied
    suffix. We strip surrounding whitespace and reject CR/LF-bearing values
    outright as a belt-and-braces guard against header injection.
    """
    raw = request.headers.get(header_name)
    if raw is None:
        return None
    cleaned = raw.strip()
    if not cleaned:
        return None
    if "\r" in cleaned or "\n" in cleaned:
        return None
    return cleaned


def _log_invalid_attempt(request: Request, *, scope: str) -> None:
    """Emit a safe audit line about an invalid auth attempt."""
    rid = getattr(request.state, "request_id", None)
    client = request.client.host if request.client else "unknown"
    # NEVER include the candidate value or any header content here.
    log.warning(
        "invalid-api-key-attempt rid=%s scope=%s client=%s path=%s",
        rid,
        scope,
        client,
        request.url.path,
    )


def require_api_key(
    request: Request,
    settings: WebSettings = Depends(get_settings),
) -> Principal:
    """Dependency: require a valid API key on the request."""
    if not settings.auth_enabled:
        if dev_auth_bypass_active(settings):
            return anonymous()
        raise AuthUnavailableError("API-key authentication is not enabled.")

    candidate = _extract_header(request, settings.api_key_header_name)
    if not candidate:
        raise AuthRequiredError(
            f"Missing required {settings.api_key_header_name} header."
        )

    if not match_api_key(candidate, accepted_api_keys(settings.api_keys, settings)):
        _log_invalid_attempt(request, scope="api")
        raise AuthForbiddenError("Invalid or insufficient API key.")

    return Principal(auth_type="api_key", scope="api")


def require_admin_api_key(
    request: Request,
    settings: WebSettings = Depends(get_settings),
) -> Principal:
    """Dependency: require a valid *admin* API key on the request."""
    # Fail closed whenever admin keys cannot be checked — API-key auth off
    # (development bypass included) or no admin keys configured. Never
    # silently downgrade an admin route to anonymous or a regular key.
    # Refused (placeholder or weak) admin keys count as not configured.
    admin_keys = accepted_api_keys(settings.admin_api_keys, settings)
    if not settings.auth_enabled or not admin_keys:
        _log_invalid_attempt(request, scope="admin-unconfigured")
        raise AuthForbiddenError("Admin operations are not configured.")

    candidate = _extract_header(request, settings.admin_api_key_header_name)
    if not candidate:
        raise AuthRequiredError(
            f"Missing required {settings.admin_api_key_header_name} header."
        )

    if not match_api_key(candidate, admin_keys):
        _log_invalid_attempt(request, scope="admin")
        raise AuthForbiddenError("Invalid or insufficient admin API key.")

    return Principal(auth_type="api_key", scope="admin")


def optional_api_key(
    request: Request,
    settings: WebSettings = Depends(get_settings),
) -> Principal:
    """
    Dependency: return a :class:`Principal` if a valid key is present, else
    the anonymous principal. Used by endpoints that are public by default
    but whose response can be enriched when authenticated.
    """
    if not settings.auth_enabled:
        return anonymous()

    candidate = _extract_header(request, settings.api_key_header_name)
    if candidate and match_api_key(candidate, accepted_api_keys(settings.api_keys, settings)):
        return Principal(auth_type="api_key", scope="api")
    return anonymous()
