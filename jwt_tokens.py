"""
JWT access / refresh token primitives (Phase 5a).

Built on PyJWT. Two token *types* are issued:

* ``access``  — short-lived (minutes), sent in the ``Authorization`` header.
* ``refresh`` — longer-lived (days), delivered only as an httpOnly cookie.

Both carry a ``jti`` (unique id) so a refresh token can be revoked server-side
(see :mod:`.token_store`). Decoding always enforces the algorithm, issuer,
audience, expiry and token type — a token minted as ``access`` can never be
replayed as ``refresh`` or vice-versa.

Security notes:

* The signing secret is passed in by the caller (from settings); this module
  never reads env directly and never logs the secret or any token.
* ``decode_token`` rejects tokens signed with a different/`none` algorithm
  because the expected algorithm is pinned on every call.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt

ACCESS_TOKEN_TYPE = "access"
REFRESH_TOKEN_TYPE = "refresh"

_ISSUER = "ioc-enricher"

# Each JWT type has a single recipient, named in the ``aud`` claim: access
# tokens are presented to the API, refresh tokens only to
# ``POST /auth/refresh``. Verification requires the audience of the token's
# own type, so neither type is accepted where the other is expected.
ACCESS_TOKEN_AUDIENCE = "ioc-enricher-api"
REFRESH_TOKEN_AUDIENCE = "ioc-enricher-auth-refresh"
_AUDIENCE_BY_TYPE = {
    ACCESS_TOKEN_TYPE: ACCESS_TOKEN_AUDIENCE,
    REFRESH_TOKEN_TYPE: REFRESH_TOKEN_AUDIENCE,
}

# Shared-secret HMAC algorithms only (see user_auth.resolve_jwt_config).
ALLOWED_ALGORITHMS = frozenset({"HS256", "HS384", "HS512"})


def _check_algorithm(algorithm: str) -> None:
    if algorithm not in ALLOWED_ALGORITHMS:
        raise TokenError("Unsupported JWT algorithm.")


class TokenError(Exception):
    """Raised for a missing, malformed or expired token, or a wrong type/audience."""


@dataclass(frozen=True)
class DecodedToken:
    """The validated claims we care about from a decoded JWT."""

    subject: str          # username
    role: str             # "admin" | "analyst"
    token_type: str       # "access" | "refresh"
    jti: str              # unique token id
    expires_at: datetime  # UTC
    # Fingerprint of the credential the token was issued for (``cfp``);
    # ``None`` for a token minted without one. Checked against the current
    # account by user_auth, not here.
    credential: Optional[str] = None


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def create_access_token(
    *,
    subject: str,
    role: str,
    secret: str,
    algorithm: str = "HS256",
    ttl_minutes: int = 15,
    credential: Optional[str] = None,
) -> tuple[str, str]:
    """
    Mint an access token. Returns ``(token, jti)``.

    *credential* is the account's credential fingerprint (``cfp`` claim).
    """
    return _create_token(
        subject=subject,
        role=role,
        secret=secret,
        algorithm=algorithm,
        token_type=ACCESS_TOKEN_TYPE,
        ttl=timedelta(minutes=max(1, ttl_minutes)),
        credential=credential,
    )


def create_refresh_token(
    *,
    subject: str,
    role: str,
    secret: str,
    algorithm: str = "HS256",
    ttl_days: int = 7,
    credential: Optional[str] = None,
) -> tuple[str, str]:
    """
    Mint a refresh token. Returns ``(token, jti)``.

    *credential* is the account's credential fingerprint (``cfp`` claim).
    """
    return _create_token(
        subject=subject,
        role=role,
        secret=secret,
        algorithm=algorithm,
        token_type=REFRESH_TOKEN_TYPE,
        ttl=timedelta(days=max(1, ttl_days)),
        credential=credential,
    )


def _create_token(
    *,
    subject: str,
    role: str,
    secret: str,
    algorithm: str,
    token_type: str,
    ttl: timedelta,
    credential: Optional[str] = None,
) -> tuple[str, str]:
    if not secret:
        raise TokenError("JWT secret is not configured.")
    _check_algorithm(algorithm)
    audience = _AUDIENCE_BY_TYPE.get(token_type)
    if audience is None:
        raise TokenError("Unsupported token type.")
    issued = _now()
    jti = uuid.uuid4().hex
    payload = {
        "sub": subject,
        "role": role,
        "type": token_type,
        "jti": jti,
        "iss": _ISSUER,
        "aud": audience,
        "iat": issued,
        "nbf": issued,
        "exp": issued + ttl,
    }
    if credential:
        payload["cfp"] = credential
    token = jwt.encode(payload, secret, algorithm=algorithm)
    # PyJWT >= 2 returns str already; normalise just in case.
    if isinstance(token, bytes):  # pragma: no cover
        token = token.decode("utf-8")
    return token, jti


def decode_token(
    token: str,
    *,
    secret: str,
    algorithm: str = "HS256",
    expected_type: Optional[str] = None,
) -> DecodedToken:
    """
    Decode and fully validate *token*.

    Raises :class:`TokenError` on any failure: bad signature, wrong algorithm,
    expired, wrong issuer or audience, missing claims, or a token-type
    mismatch when *expected_type* is given. The ``aud`` claim must be exactly
    the audience issued for the token's own type.
    """
    if not token or not secret:
        raise TokenError("Missing token or signing secret.")
    _check_algorithm(algorithm)
    if expected_type is None:
        audience = list(_AUDIENCE_BY_TYPE.values())
    elif expected_type in _AUDIENCE_BY_TYPE:
        audience = _AUDIENCE_BY_TYPE[expected_type]
    else:
        raise TokenError("Unsupported token type.")
    try:
        claims = jwt.decode(
            token,
            secret,
            algorithms=[algorithm],
            issuer=_ISSUER,
            audience=audience,
            options={"require": ["exp", "iat", "sub", "jti", "aud"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("Token has expired.") from exc
    except jwt.InvalidTokenError as exc:
        # Covers bad signature, wrong alg, missing claims, bad issuer, etc.
        raise TokenError("Token is invalid.") from exc

    token_type = claims.get("type")
    if expected_type is not None and token_type != expected_type:
        raise TokenError("Token type mismatch.")

    subject = claims.get("sub")
    role = claims.get("role")
    jti = claims.get("jti")
    if not subject or not role or not jti or not token_type:
        raise TokenError("Token is missing required claims.")

    # PyJWT accepts a token naming any listed audience; require exactly the
    # one issued for this token's type (rejects multi-audience and cross-type).
    if claims.get("aud") != _AUDIENCE_BY_TYPE.get(token_type):
        raise TokenError("Token audience does not match its type.")

    exp_ts = claims.get("exp")
    expires_at = datetime.fromtimestamp(float(exp_ts), tz=timezone.utc)
    credential = claims.get("cfp")

    return DecodedToken(
        subject=str(subject),
        role=str(role),
        token_type=str(token_type),
        jti=str(jti),
        expires_at=expires_at,
        credential=credential if isinstance(credential, str) else None,
    )


def validate_token_type(decoded: DecodedToken, expected: str) -> None:
    """Raise :class:`TokenError` unless *decoded* is of *expected* type."""
    if decoded.token_type != expected:
        raise TokenError("Token type mismatch.")
