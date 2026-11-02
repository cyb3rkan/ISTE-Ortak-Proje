"""
Regression tests for N-1: every JWT carries a fixed audience and the verifier
requires it.

Each JWT type has its own recipient, so each gets its own audience: access
tokens are presented to the API, refresh tokens only to
``POST /auth/refresh``. The CSRF token is a random string, not a JWT, and has
no audience.

Upgrade impact: tokens minted before this change carry no ``aud`` and are
rejected, so existing sessions must sign in once more (see SECURITY.md).
"""
from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi.testclient import TestClient

from ioc_enricher.web.api.app import create_app
from ioc_enricher.web.api.deps import get_enrichment_service
from ioc_enricher.web.api.security.jwt_tokens import (
    ACCESS_TOKEN_TYPE,
    REFRESH_TOKEN_TYPE,
    TokenError,
    create_access_token,
    create_refresh_token,
    decode_token,
)
from ioc_enricher.web.api.security.password import hash_password
from ioc_enricher.web.settings import WebSettings

from ..conftest import FakeService

_SECRET = secrets.token_hex(32)
# The audience values are part of the token contract, so they are spelled out
# here instead of being imported from the code under test.
_API_AUDIENCE = "ioc-enricher-api"
_REFRESH_AUDIENCE = "ioc-enricher-auth-refresh"
_USER = "admin"
_PASS = "AdminStrongPass123"


def _claims(
    token_type: str,
    *,
    aud=None,
    iss: str = "ioc-enricher",
    expired: bool = False,
) -> dict:
    now = datetime.now(tz=timezone.utc)
    issued = now - timedelta(hours=1)
    claims = {
        "sub": _USER,
        "role": "admin",
        "type": token_type,
        "jti": secrets.token_hex(16),
        "iss": iss,
        "iat": issued,
        "nbf": issued,
        "exp": now - timedelta(minutes=5) if expired else now + timedelta(minutes=10),
    }
    if aud is not None:
        claims["aud"] = aud
    return claims


def _sign(claims: dict, *, algorithm: str = "HS256") -> str:
    return jwt.encode(claims, _SECRET, algorithm=algorithm)


class TestIssuedTokensNameTheirAudience:
    def test_access_token_is_issued_for_the_api(self) -> None:
        token, _ = create_access_token(subject="u", role="analyst", secret=_SECRET)
        claims = jwt.decode(
            token, _SECRET, algorithms=["HS256"], audience=_API_AUDIENCE
        )
        assert claims["aud"] == _API_AUDIENCE

    def test_refresh_token_is_issued_for_the_refresh_endpoint(self) -> None:
        token, _ = create_refresh_token(subject="u", role="analyst", secret=_SECRET)
        claims = jwt.decode(
            token, _SECRET, algorithms=["HS256"], audience=_REFRESH_AUDIENCE
        )
        assert claims["aud"] == _REFRESH_AUDIENCE


class TestVerifierRequiresAudience:
    @pytest.mark.parametrize(
        "token_type, audience",
        [
            pytest.param(ACCESS_TOKEN_TYPE, _API_AUDIENCE, id="access"),
            pytest.param(REFRESH_TOKEN_TYPE, _REFRESH_AUDIENCE, id="refresh"),
        ],
    )
    def test_matching_audience_is_accepted(self, token_type: str, audience: str) -> None:
        decoded = decode_token(
            _sign(_claims(token_type, aud=audience)),
            secret=_SECRET,
            expected_type=token_type,
        )
        assert decoded.token_type == token_type

    @pytest.mark.parametrize("token_type", [ACCESS_TOKEN_TYPE, REFRESH_TOKEN_TYPE])
    def test_missing_audience_is_rejected(self, token_type: str) -> None:
        with pytest.raises(TokenError):
            decode_token(
                _sign(_claims(token_type)), secret=_SECRET, expected_type=token_type
            )

    @pytest.mark.parametrize(
        "token_type, aud",
        [
            pytest.param(ACCESS_TOKEN_TYPE, "another-service", id="access-foreign"),
            pytest.param(ACCESS_TOKEN_TYPE, _REFRESH_AUDIENCE, id="access-with-refresh-aud"),
            pytest.param(REFRESH_TOKEN_TYPE, _API_AUDIENCE, id="refresh-with-api-aud"),
            pytest.param(
                ACCESS_TOKEN_TYPE, [_API_AUDIENCE, "another-service"], id="access-multi-aud"
            ),
        ],
    )
    def test_wrong_audience_is_rejected(self, token_type: str, aud) -> None:
        with pytest.raises(TokenError):
            decode_token(
                _sign(_claims(token_type, aud=aud)),
                secret=_SECRET,
                expected_type=token_type,
            )

    def test_audience_must_match_type_when_any_type_is_accepted(self) -> None:
        token = _sign(_claims(ACCESS_TOKEN_TYPE, aud=_REFRESH_AUDIENCE))
        with pytest.raises(TokenError):
            decode_token(token, secret=_SECRET)

    def test_type_claim_still_checked_when_audience_matches(self) -> None:
        # The refresh audience alone does not make an access-typed token a
        # refresh token: type and audience are enforced independently.
        token = _sign(_claims(ACCESS_TOKEN_TYPE, aud=_REFRESH_AUDIENCE))
        with pytest.raises(TokenError):
            decode_token(token, secret=_SECRET, expected_type=REFRESH_TOKEN_TYPE)


class TestExistingChecksStillApply:
    def test_expired_token_rejected(self) -> None:
        token = _sign(_claims(ACCESS_TOKEN_TYPE, aud=_API_AUDIENCE, expired=True))
        with pytest.raises(TokenError, match="expired"):
            decode_token(token, secret=_SECRET, expected_type=ACCESS_TOKEN_TYPE)

    def test_wrong_issuer_rejected(self) -> None:
        token = _sign(_claims(ACCESS_TOKEN_TYPE, aud=_API_AUDIENCE, iss="someone-else"))
        with pytest.raises(TokenError):
            decode_token(token, secret=_SECRET, expected_type=ACCESS_TOKEN_TYPE)

    def test_other_algorithm_rejected(self) -> None:
        token = _sign(_claims(ACCESS_TOKEN_TYPE, aud=_API_AUDIENCE), algorithm="HS512")
        with pytest.raises(TokenError):
            decode_token(
                token, secret=_SECRET, algorithm="HS256", expected_type=ACCESS_TOKEN_TYPE
            )


@pytest.fixture(scope="module")
def admin_hash() -> str:
    return hash_password(_PASS)


def _client(admin_hash: str) -> TestClient:
    app = create_app(
        WebSettings(
            user_auth_enabled=True,
            jwt_secret_key=_SECRET,
            bootstrap_admin_username=_USER,
            bootstrap_admin_password_hash=admin_hash,
            rate_limit_enabled=False,
        )
    )
    app.dependency_overrides[get_enrichment_service] = lambda: FakeService()
    return TestClient(app, raise_server_exceptions=False)


class TestSessionsFromBeforeTheUpgrade:
    """Tokens minted without ``aud`` (pre-upgrade sessions) stop working."""

    def test_access_token_without_audience_gets_401(self, admin_hash: str) -> None:
        client = _client(admin_hash)
        token = _sign(_claims(ACCESS_TOKEN_TYPE))
        r = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 401

    def test_refresh_cookie_without_audience_gets_401(self, admin_hash: str) -> None:
        client = _client(admin_hash)
        csrf = secrets.token_urlsafe(16)
        client.cookies.set("ioc_refresh_token", _sign(_claims(REFRESH_TOKEN_TYPE)))
        client.cookies.set("ioc_csrf_token", csrf)
        r = client.post("/api/v1/auth/refresh", headers={"X-CSRF-Token": csrf})
        assert r.status_code == 401
        assert "access_token" not in r.text

    def test_new_login_session_keeps_working(self, admin_hash: str) -> None:
        client = _client(admin_hash)
        login = client.post(
            "/api/v1/auth/login", json={"username": _USER, "password": _PASS}
        )
        assert login.status_code == 200
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        assert client.get("/api/v1/auth/me", headers=headers).status_code == 200
        csrf = client.cookies.get("ioc_csrf_token")
        refreshed = client.post("/api/v1/auth/refresh", headers={"X-CSRF-Token": csrf})
        assert refreshed.status_code == 200
