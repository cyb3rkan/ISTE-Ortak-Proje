"""
User-authentication policy and FastAPI dependencies (Phase 5a).

This sits *alongside* the API-key policy in :mod:`.policies` — it does not
replace it. The combined dependencies (``require_api_key_or_user`` etc.)
accept *either* a valid API key (server-to-server) *or* a valid user JWT
(browser), so the existing API-key flow keeps working unchanged.

Auth-state matrix for a protected route:

    user_auth_enabled  auth_enabled   behaviour
    ─────────────────  ────────────   ─────────────────────────────────────
    False              False          closed: 503 — open only under the
                                      development bypass (debug mode,
                                      IOC_WEB_DEV_ALLOW_UNAUTHENTICATED)
    False              True           API key required
    True               False          user JWT required
    True               True           API key OR user JWT accepted

Admin routes never accept an anonymous request, in any of these states.

Nothing here logs a password, token, or JWT secret.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
from dataclasses import dataclass, field
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
)
from .jwt_tokens import (
    ACCESS_TOKEN_TYPE,
    ALLOWED_ALGORITHMS,
    DecodedToken,
    TokenError,
    decode_token,
)
from .password import verify_password
from .policies import _extract_header, dev_auth_bypass_active
from .secret_strength import (
    accepted_api_keys,
    api_key_problem,
    is_public_secret,
    is_strong_secret,
)

log = logging.getLogger("ioc_enricher.web.auth")

# Roles, ordered weakest -> strongest.
ROLE_ANALYST = "analyst"
ROLE_ADMIN = "admin"
_VALID_ROLES = frozenset({ROLE_ANALYST, ROLE_ADMIN})

# Only symmetric HMAC algorithms are supported: the signing key is a shared
# secret string. Asymmetric algorithms (RS*/ES*/PS*/EdDSA) and ``none`` are
# rejected outright so a misconfigured env var can never enable algorithm
# confusion or unsigned tokens.
ALLOWED_JWT_ALGORITHMS = ALLOWED_ALGORITHMS


@dataclass(frozen=True)
class AuthenticatedUser:
    """A successfully authenticated browser user."""

    username: str
    role: str


# ---------------------------------------------------------------------------
# Configuration guards
# ---------------------------------------------------------------------------

class AuthConfigError(Exception):
    """
    Raised when the auth configuration is unusable: mapped to 503 when user
    auth is misconfigured, or raised from ``create_app`` for a setting that
    must never reach production.
    """


def is_strong_jwt_secret(secret: Optional[str]) -> bool:
    """Return ``True`` iff *secret* meets the strong-secret bar."""
    return is_strong_secret(secret)


def assert_jwt_secret_usable(settings: WebSettings) -> str:
    """
    Validate the configured JWT secret and return it.

    Raises :class:`AuthConfigError` when:

    * no secret is configured,
    * the secret is a documented placeholder or a well-known weak value — in
      every mode, debug included, because such a value is public, or
    * the secret is otherwise weak (short, repetitive, sequential). Debug
      mode is held to the same bar; only an explicit
      ``require_strong_jwt_secret_in_prod=False`` in a production-like
      deployment skips this check.
    """
    secret = settings.jwt_secret_key
    if not secret:
        raise AuthConfigError("JWT signing secret is not configured.")

    if is_public_secret(secret):
        raise AuthConfigError(
            "JWT signing secret is a placeholder or a well-known weak value."
        )

    # A generated secret costs nothing locally, while a guessable one mints
    # valid admin tokens wherever the debug configuration ends up running.
    enforce_strength = settings.debug or settings.require_strong_jwt_secret_in_prod
    if enforce_strength and not is_strong_jwt_secret(secret):
        raise AuthConfigError(
            "JWT signing secret is too weak: use at least 32 generated random "
            "characters."
        )
    return secret


@dataclass(frozen=True)
class JwtConfig:
    """A validated (secret, algorithm) pair. Never logged or serialised."""

    secret: str = field(repr=False)
    algorithm: str


def resolve_jwt_config(settings: WebSettings) -> JwtConfig:
    """
    Single source of truth for the JWT signing policy.

    Every code path that mints *or* verifies a token must go through here so
    the secret-strength and algorithm rules cannot drift apart between the
    ``/auth/*`` routes and the protected-route dependencies.

    Raises :class:`AuthConfigError` when the algorithm is not an allowed HMAC
    algorithm (enforced even in debug) or the secret is missing / too weak
    (see :func:`assert_jwt_secret_usable`).
    """
    algorithm = settings.jwt_algorithm
    if algorithm not in ALLOWED_JWT_ALGORITHMS:
        raise AuthConfigError("JWT algorithm is not an allowed HMAC algorithm.")
    secret = assert_jwt_secret_usable(settings)
    return JwtConfig(secret=secret, algorithm=algorithm)


def assert_dev_auth_bypass_allowed(settings: WebSettings) -> None:
    """
    Startup check: refuse to build the app when the development auth bypass
    is switched on outside debug mode — that must never reach production.
    """
    if settings.dev_allow_unauthenticated and not settings.debug:
        raise AuthConfigError(
            "IOC_WEB_DEV_ALLOW_UNAUTHENTICATED is for local development only and "
            "requires IOC_WEB_DEBUG=true; refusing to start."
        )


def log_auth_config_problems(settings: WebSettings) -> bool:
    """
    Startup check: log (without the secret) when no auth mode is configured or
    user auth is enabled but the JWT configuration is unusable. Returns
    ``True`` when the configuration is usable.

    The app still starts so that ``/health`` stays reachable for operators,
    but every unusable path fails closed (503 on protected routes and
    ``/auth/*``, 403 on admin routes, no user principal) until it is fixed.
    """
    if settings.auth_enabled:
        _log_refused_api_keys(settings)
    if not settings.user_auth_enabled:
        if settings.auth_enabled:
            return True
        if dev_auth_bypass_active(settings):
            log.warning(
                "auth-dev-bypass: IOC_WEB_DEV_ALLOW_UNAUTHENTICATED is on, so "
                "every non-admin endpoint is public; admin endpoints stay "
                "closed. Local development only."
            )
            return True
        log.error(
            "auth-not-configured: neither API-key nor user authentication is "
            "enabled; protected endpoints answer 503 and admin endpoints 403. "
            "Set IOC_WEB_AUTH_ENABLED or IOC_WEB_USER_AUTH_ENABLED."
        )
        return False
    try:
        resolve_jwt_config(settings)
    except AuthConfigError as exc:
        log.error("auth-misconfigured: %s User authentication is disabled "
                  "until this is fixed.", exc)
        return False
    return True


def _log_refused_api_keys(settings: WebSettings) -> None:
    """Startup notice for configured keys that authenticate nothing (counts only)."""
    refused = {"API key(s)": settings.api_keys, "admin key(s)": settings.admin_api_keys}
    parts = []
    for label, keys in refused.items():
        problems = [api_key_problem(key, settings) for key in keys]
        bad = [p for p in problems if p]
        if bad:
            reasons = ", ".join(sorted(set(bad)))
            parts.append(f"{len(bad)} of {len(keys)} {label} ({reasons})")
    if parts:
        log.warning(
            "api-key-rejected: %s ignored — documented placeholders and weak keys "
            "never authenticate. Generate keys with "
            "python -c \"import secrets; print(secrets.token_urlsafe(32))\".",
            "; ".join(parts),
        )


# ---------------------------------------------------------------------------
# Bootstrap user authentication
# ---------------------------------------------------------------------------

def authenticate_bootstrap_user(
    settings: WebSettings, username: str, password: str
) -> Optional[AuthenticatedUser]:
    """
    Verify *username*/*password* against the configured bootstrap admin.

    Returns an :class:`AuthenticatedUser` on success, ``None`` on any failure.
    The failure path is deliberately uniform (no "unknown user" vs "bad
    password" distinction) so the caller can return a single generic 401.
    """
    expected_username = settings.bootstrap_admin_username
    stored_hash = settings.bootstrap_admin_password_hash
    if not expected_username or not stored_hash:
        return None
    if not username or not password:
        return None

    # Compare username case-sensitively but still run verify_password even on
    # a username mismatch so timing does not reveal which field was wrong.
    username_ok = username == expected_username
    password_ok = verify_password(password, stored_hash)
    if not (username_ok and password_ok):
        return None

    return AuthenticatedUser(
        username=expected_username, role=_bootstrap_role(settings)
    )


def _bootstrap_role(settings: WebSettings) -> str:
    role = settings.bootstrap_admin_role
    return role if role in _VALID_ROLES else ROLE_ADMIN


def current_account(settings: WebSettings, username: str) -> Optional[AuthenticatedUser]:
    """
    Return the *current* state of account *username*, or ``None`` if it no
    longer exists / can no longer log in.

    Used on refresh so role changes and account removal take effect at the
    next rotation instead of being carried forward forever by the token.
    """
    expected_username = settings.bootstrap_admin_username
    if not expected_username or not settings.bootstrap_admin_password_hash:
        return None
    if username != expected_username:
        return None
    return AuthenticatedUser(username=expected_username, role=_bootstrap_role(settings))


def credential_fingerprint(settings: WebSettings, secret: str) -> Optional[str]:
    """
    Fingerprint of the bootstrap account's current credential, carried by
    every issued token as the ``cfp`` claim: changing the password hash (or
    the username) ends the sessions issued before. It is an HMAC keyed with
    the signing secret, so the claim says nothing about the hash itself.
    """
    username = settings.bootstrap_admin_username
    stored_hash = settings.bootstrap_admin_password_hash
    if not username or not stored_hash or not secret:
        return None
    message = f"ioc-enricher-credential:{len(username)}:{username}:{stored_hash}"
    digest = hmac.new(secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256)
    return digest.hexdigest()[:32]


def account_for_token(settings: WebSettings, decoded: DecodedToken) -> Optional[AuthenticatedUser]:
    """
    The current account a decoded token may act for, or ``None``.

    The account must still exist and the token must carry the fingerprint of
    its current credential; a token issued before a password change (or
    without a fingerprint) authenticates nothing.
    """
    account = current_account(settings, decoded.subject)
    if account is None:
        return None
    try:
        secret = resolve_jwt_config(settings).secret
    except AuthConfigError:
        return None
    expected = credential_fingerprint(settings, secret)
    if not expected or not decoded.credential:
        return None
    if not hmac.compare_digest(decoded.credential, expected):
        return None
    return account


# ---------------------------------------------------------------------------
# Bearer-token extraction
# ---------------------------------------------------------------------------

def _extract_bearer(request: Request) -> Optional[str]:
    """Pull the bearer token from the ``Authorization`` header, if present."""
    raw = request.headers.get("Authorization")
    if not raw:
        return None
    parts = raw.strip().split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    token = parts[1].strip()
    if not token or "\r" in token or "\n" in token:
        return None
    return token


def _decode_access_from_request(
    request: Request, settings: WebSettings
) -> Optional[DecodedToken]:
    """
    Decode a valid *access* JWT from the request, or return ``None``.

    Returns ``None`` for both "no token presented" and "token invalid" — the
    caller decides whether the absence is a 401.
    """
    token = _extract_bearer(request)
    if not token:
        return None
    try:
        # Same policy as the /auth routes: a weak secret or disallowed
        # algorithm means *no* token is trusted (fail closed).
        config = resolve_jwt_config(settings)
    except AuthConfigError:
        return None
    try:
        return decode_token(
            token,
            secret=config.secret,
            algorithm=config.algorithm,
            expected_type=ACCESS_TOKEN_TYPE,
        )
    except TokenError:
        return None


# ---------------------------------------------------------------------------
# FastAPI dependencies
# ---------------------------------------------------------------------------

def get_current_user(
    request: Request,
    settings: WebSettings = Depends(get_settings),
) -> Optional[AuthenticatedUser]:
    """
    Return the authenticated user if a valid access token is present, else
    ``None``. Never raises — use :func:`require_user` to enforce presence.
    """
    if not settings.user_auth_enabled:
        return None
    decoded = _decode_access_from_request(request, settings)
    if decoded is None:
        return None
    # The token must belong to the account as it is now; its role is the
    # account's current one.
    return account_for_token(settings, decoded)


def require_user(
    request: Request,
    settings: WebSettings = Depends(get_settings),
) -> AuthenticatedUser:
    """Dependency: require a valid user access token."""
    user = get_current_user(request, settings)
    if user is None:
        raise AuthRequiredError("A valid access token is required.")
    return user


def require_admin_user(
    request: Request,
    settings: WebSettings = Depends(get_settings),
) -> AuthenticatedUser:
    """Dependency: require a valid user access token with the admin role."""
    user = require_user(request, settings)
    if user.role != ROLE_ADMIN:
        raise AuthForbiddenError("Administrator privileges are required.")
    return user


# --- combined API-key OR user-JWT policies ---------------------------------

def require_api_key_or_user(
    request: Request,
    settings: WebSettings = Depends(get_settings),
) -> Principal:
    """
    Dependency for standard protected routes.

    Accepts a valid API key (server-to-server) OR a valid user access token
    (browser). When neither auth mode is enabled the route fails closed
    (503), unless the development bypass is active.
    """
    api_key_active = settings.auth_enabled
    user_active = settings.user_auth_enabled

    if not api_key_active and not user_active:
        if dev_auth_bypass_active(settings):
            return anonymous()
        raise AuthUnavailableError("Authentication is not configured on this server.")

    # Try user JWT first — it is the browser path and never logs on miss.
    if user_active:
        user = get_current_user(request, settings)
        if user is not None:
            return Principal(auth_type="user", scope=user.role)

    # Then the API-key path.
    if api_key_active:
        candidate = _extract_header(request, settings.api_key_header_name)
        if candidate:
            from .auth import match_api_key

            if match_api_key(candidate, accepted_api_keys(settings.api_keys, settings)):
                return Principal(auth_type="api_key", scope="api")
            _log_invalid(request, scope="api")
            raise AuthForbiddenError("Invalid or insufficient API key.")

    # Nothing valid presented.
    raise AuthRequiredError("Authentication is required for this endpoint.")


def require_admin_api_key_or_admin_user(
    request: Request,
    settings: WebSettings = Depends(get_settings),
) -> Principal:
    """
    Dependency for admin routes (``DELETE /cache``).

    Accepts a valid *admin* API key OR a valid user token carrying the admin
    role. Fails closed when no auth mode is enabled — the development bypass
    included — or admin auth is enabled but unconfigured.
    """
    api_key_active = settings.auth_enabled
    user_active = settings.user_auth_enabled

    if not api_key_active and not user_active:
        _log_invalid(request, scope="admin-unconfigured")
        raise AuthForbiddenError("Admin operations are not configured.")

    # User JWT path — admin role required.
    if user_active:
        user = get_current_user(request, settings)
        if user is not None:
            if user.role == ROLE_ADMIN:
                return Principal(auth_type="user", scope=ROLE_ADMIN)
            _log_invalid(request, scope="admin")
            raise AuthForbiddenError("Administrator privileges are required.")

    # Admin API-key path. Refused (placeholder or weak) admin keys count as
    # not configured.
    if api_key_active:
        admin_keys = accepted_api_keys(settings.admin_api_keys, settings)
        if not admin_keys:
            _log_invalid(request, scope="admin-unconfigured")
            raise AuthForbiddenError("Admin operations are not configured.")
        candidate = _extract_header(request, settings.admin_api_key_header_name)
        if candidate:
            from .auth import match_api_key

            if match_api_key(candidate, admin_keys):
                return Principal(auth_type="api_key", scope="admin")
            _log_invalid(request, scope="admin")
            raise AuthForbiddenError("Invalid or insufficient admin API key.")

    raise AuthRequiredError("Administrator authentication is required.")


def _log_invalid(request: Request, *, scope: str) -> None:
    """Emit a safe audit line — never includes the candidate credential."""
    rid = getattr(request.state, "request_id", None)
    client = request.client.host if request.client else "unknown"
    log.warning(
        "invalid-auth-attempt rid=%s scope=%s client=%s path=%s",
        rid,
        scope,
        client,
        request.url.path,
    )
