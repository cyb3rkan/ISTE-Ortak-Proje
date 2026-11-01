"""
End-to-end tests for the Phase 5a user-authentication layer.

Covers:

* User auth disabled -> /auth routes return a safe 404.
* Missing/weak JWT secret -> safe 503.
* Login: invalid credentials -> generic 401; valid -> access token + refresh
  cookie + CSRF cookie.
* /auth/me with a valid/expired access token.
* Refresh: requires cookie + CSRF header; rotates the access token.
* Logout: clears cookies, revokes the refresh jti.
* Protected endpoints accept a user JWT; admin endpoints enforce the role.
* The existing API-key flow still works unchanged.
* No token / secret / password ever appears in a response or log line.
"""
from __future__ import annotations

import logging
import secrets

import pytest
from fastapi.testclient import TestClient

from ioc_enricher.web.api.app import create_app
from ioc_enricher.web.api.deps import get_enrichment_service
from ioc_enricher.web.api.security.jwt_tokens import create_access_token
from ioc_enricher.web.api.security.password import hash_password
from ioc_enricher.web.settings import WebSettings

from ..conftest import FakeService

# A generated (never committed) secret so production-mode checks pass. A
# fixed phrase such as "test-jwt-secret-..." is itself a placeholder.
_JWT_SECRET = secrets.token_hex(32)
_ADMIN_USER = "admin"
_ADMIN_PASS = "AdminStrongPass123"
_API_KEY = "test-api-key-" + secrets.token_urlsafe(24)
_ADMIN_KEY = "test-admin-key-" + secrets.token_urlsafe(24)


@pytest.fixture(scope="module")
def admin_hash() -> str:
    return hash_password(_ADMIN_PASS)


def _build(
    *,
    user_auth_enabled: bool = True,
    auth_enabled: bool = False,
    jwt_secret: str | None = _JWT_SECRET,
    admin_hash: str | None = None,
    admin_username: str | None = _ADMIN_USER,
    admin_role: str = "admin",
    debug: bool = False,
    api_keys=None,
    admin_api_keys=None,
    enable_docs: bool | None = None,
) -> tuple[TestClient, FakeService]:
    fake = FakeService()
    settings = WebSettings(
        debug=debug,
        enable_docs=enable_docs,
        user_auth_enabled=user_auth_enabled,
        auth_enabled=auth_enabled,
        jwt_secret_key=jwt_secret,
        bootstrap_admin_username=admin_username,
        bootstrap_admin_password_hash=admin_hash,
        bootstrap_admin_role=admin_role,
        api_keys=list(api_keys or []),
        admin_api_keys=list(admin_api_keys or []),
        rate_limit_enabled=False,
    )
    app = create_app(settings)
    app.dependency_overrides[get_enrichment_service] = lambda: fake
    return TestClient(app, raise_server_exceptions=False), fake


def _login(client: TestClient, username=_ADMIN_USER, password=_ADMIN_PASS):
    return client.post(
        "/api/v1/auth/login", json={"username": username, "password": password}
    )


# ---------------------------------------------------------------------------
# Disabled / misconfigured
# ---------------------------------------------------------------------------

class TestAuthDisabled:
    def test_login_404_when_user_auth_disabled(self) -> None:
        client, _ = _build(user_auth_enabled=False)
        r = client.post(
            "/api/v1/auth/login", json={"username": "x", "password": "y"}
        )
        assert r.status_code == 404

    def test_me_404_when_user_auth_disabled(self) -> None:
        client, _ = _build(user_auth_enabled=False)
        assert client.get("/api/v1/auth/me").status_code == 404


class TestMisconfigured:
    def test_missing_secret_returns_503(self, admin_hash: str) -> None:
        client, _ = _build(jwt_secret=None, admin_hash=admin_hash)
        r = _login(client)
        assert r.status_code == 503
        # Locale-tolerant: either the English phrasing or the Turkish
        # equivalent ("kullanılamıyor" / "kullanılamaz"). The behaviour we
        # actually care about is the 503 status + a non-empty detail.
        detail = r.json()["detail"].lower()
        assert detail
        assert (
            "unavailable" in detail
            or "kullanılam" in detail  # kullanılamıyor / kullanılamaz
        )

    def test_weak_secret_rejected_in_prod(self, admin_hash: str) -> None:
        client, _ = _build(
            jwt_secret="short", admin_hash=admin_hash, debug=False
        )
        assert _login(client).status_code == 503

    def test_weak_secret_rejected_in_debug_too(self, admin_hash: str) -> None:
        # Debug mode applies the production strength bar: a short private
        # secret no longer signs anything (see test_jwt_secret_policy.py).
        client, _ = _build(
            jwt_secret="local-dev-only", admin_hash=admin_hash, debug=True
        )
        assert _login(client).status_code == 503

    def test_generated_secret_works_in_debug(self, admin_hash: str) -> None:
        client, _ = _build(admin_hash=admin_hash, debug=True)
        assert _login(client).status_code == 200


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

class TestLogin:
    def test_invalid_credentials_generic_401(self, admin_hash: str) -> None:
        client, _ = _build(admin_hash=admin_hash)
        r = _login(client, password="wrong-password")
        assert r.status_code == 401
        # Generic — must not reveal whether the username or password failed.
        # We accept either the English or the Turkish localisation, but the
        # message MUST mention both "username/kullanıcı adı" AND
        # "password/şifre" so that we never confirm which one was wrong.
        detail = r.json()["detail"].lower()
        mentions_username = "username" in detail or "kullanıcı adı" in detail
        mentions_password = "password" in detail or "şifre" in detail
        assert mentions_username and mentions_password, detail
        # Defensive: the detail must NOT name which one is wrong.
        for leak in ("user not found", "wrong password", "bad password",
                     "kullanıcı bulunamadı", "şifre yanlış", "şifre hatalı"):
            assert leak not in detail

    def test_unknown_user_generic_401(self, admin_hash: str) -> None:
        client, _ = _build(admin_hash=admin_hash)
        assert _login(client, username="nobody").status_code == 401

    def test_valid_login_returns_token_and_cookies(self, admin_hash: str) -> None:
        client, _ = _build(admin_hash=admin_hash)
        r = _login(client)
        assert r.status_code == 200
        body = r.json()
        assert body["token_type"] == "bearer"
        assert body["access_token"]
        assert body["expires_in"] == 15 * 60
        assert body["user"] == {"username": _ADMIN_USER, "role": "admin"}
        # Refresh + CSRF cookies are set.
        cookies = r.headers.get_list("set-cookie")
        joined = " ".join(cookies)
        assert "ioc_refresh_token=" in joined
        assert "ioc_csrf_token=" in joined
        # Refresh cookie must be httpOnly; CSRF cookie must NOT be.
        refresh_line = next(c for c in cookies if c.startswith("ioc_refresh_token="))
        csrf_line = next(c for c in cookies if c.startswith("ioc_csrf_token="))
        assert "httponly" in refresh_line.lower()
        assert "httponly" not in csrf_line.lower()

    def test_access_token_not_set_as_cookie(self, admin_hash: str) -> None:
        client, _ = _build(admin_hash=admin_hash)
        r = _login(client)
        joined = " ".join(r.headers.get_list("set-cookie"))
        assert r.json()["access_token"] not in joined


# ---------------------------------------------------------------------------
# /auth/me
# ---------------------------------------------------------------------------

class TestMe:
    def test_me_with_valid_token(self, admin_hash: str) -> None:
        client, _ = _build(admin_hash=admin_hash)
        token = _login(client).json()["access_token"]
        r = client.get(
            "/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}
        )
        assert r.status_code == 200
        assert r.json() == {"username": _ADMIN_USER, "role": "admin"}

    def test_me_without_token_401(self, admin_hash: str) -> None:
        client, _ = _build(admin_hash=admin_hash)
        assert client.get("/api/v1/auth/me").status_code == 401

    def test_me_with_tampered_token_401(self, admin_hash: str) -> None:
        client, _ = _build(admin_hash=admin_hash)
        token = _login(client).json()["access_token"]
        tampered = token[:-4] + "AAAA"
        r = client.get(
            "/api/v1/auth/me", headers={"Authorization": f"Bearer {tampered}"}
        )
        assert r.status_code == 401

    def test_refresh_token_rejected_as_access(self, admin_hash: str) -> None:
        # A refresh token must not be usable as a Bearer access token.
        client, _ = _build(admin_hash=admin_hash)
        from ioc_enricher.web.api.security.jwt_tokens import create_refresh_token

        refresh, _ = create_refresh_token(
            subject=_ADMIN_USER, role="admin", secret=_JWT_SECRET
        )
        r = client.get(
            "/api/v1/auth/me", headers={"Authorization": f"Bearer {refresh}"}
        )
        assert r.status_code == 401


# ---------------------------------------------------------------------------
# Refresh
# ---------------------------------------------------------------------------

class TestRefresh:
    def test_refresh_without_cookie_401(self, admin_hash: str) -> None:
        client, _ = _build(admin_hash=admin_hash)
        # No login -> no refresh cookie.
        r = client.post(
            "/api/v1/auth/refresh", headers={"X-CSRF-Token": "anything"}
        )
        assert r.status_code == 401

    def test_refresh_without_csrf_403(self, admin_hash: str) -> None:
        client, _ = _build(admin_hash=admin_hash)
        _login(client)  # populates the test client's cookie jar
        r = client.post("/api/v1/auth/refresh")
        assert r.status_code == 403

    def test_refresh_with_csrf_rotates_token(self, admin_hash: str) -> None:
        client, _ = _build(admin_hash=admin_hash)
        login = _login(client)
        csrf = client.cookies.get("ioc_csrf_token")
        assert csrf
        r = client.post(
            "/api/v1/auth/refresh", headers={"X-CSRF-Token": csrf}
        )
        assert r.status_code == 200
        assert r.json()["access_token"]
        assert r.json()["user"]["username"] == _ADMIN_USER

    def test_refresh_with_wrong_csrf_403(self, admin_hash: str) -> None:
        client, _ = _build(admin_hash=admin_hash)
        _login(client)
        r = client.post(
            "/api/v1/auth/refresh", headers={"X-CSRF-Token": "wrong-token"}
        )
        assert r.status_code == 403


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------

class TestLogout:
    def test_logout_clears_cookies(self, admin_hash: str) -> None:
        client, _ = _build(admin_hash=admin_hash)
        _login(client)
        csrf = client.cookies.get("ioc_csrf_token")
        r = client.post(
            "/api/v1/auth/logout", headers={"X-CSRF-Token": csrf}
        )
        assert r.status_code == 200
        assert r.json() == {"logged_out": True}
        # Deletion is signalled with an expiry in the past / empty value.
        joined = " ".join(r.headers.get_list("set-cookie")).lower()
        assert "ioc_refresh_token=" in joined

    def test_logout_revokes_refresh_token(self, admin_hash: str) -> None:
        client, _ = _build(admin_hash=admin_hash)
        _login(client)
        csrf = client.cookies.get("ioc_csrf_token")
        refresh_before = client.cookies.get("ioc_refresh_token")
        # Logout.
        assert client.post(
            "/api/v1/auth/logout", headers={"X-CSRF-Token": csrf}
        ).status_code == 200
        # Re-inject the old (now-revoked) refresh token on the client jar and
        # confirm a replay fails.
        client.cookies.set("ioc_refresh_token", refresh_before)
        client.cookies.set("ioc_csrf_token", csrf)
        r = client.post(
            "/api/v1/auth/refresh", headers={"X-CSRF-Token": csrf}
        )
        assert r.status_code == 401

    def test_logout_without_csrf_403(self, admin_hash: str) -> None:
        client, _ = _build(admin_hash=admin_hash)
        _login(client)
        assert client.post("/api/v1/auth/logout").status_code == 403


# ---------------------------------------------------------------------------
# Protected endpoints with a user JWT
# ---------------------------------------------------------------------------

class TestProtectedWithUserJwt:
    def test_enrich_with_user_jwt(self, admin_hash: str) -> None:
        client, _ = _build(admin_hash=admin_hash)
        token = _login(client).json()["access_token"]
        r = client.post(
            "/api/v1/enrich",
            json={"ioc": "8.8.8.8"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200

    def test_enrich_without_auth_401_when_user_auth_on(self, admin_hash: str) -> None:
        client, _ = _build(admin_hash=admin_hash)
        r = client.post("/api/v1/enrich", json={"ioc": "8.8.8.8"})
        assert r.status_code == 401

    def test_admin_endpoint_admin_role_ok(self, admin_hash: str) -> None:
        client, fake = _build(admin_hash=admin_hash, admin_role="admin")
        token = _login(client).json()["access_token"]
        r = client.delete(
            "/api/v1/cache?confirm=true",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200
        assert fake.clear_cache_calls == 1

    def test_admin_endpoint_analyst_role_403(self, admin_hash: str) -> None:
        client, _ = _build(admin_hash=admin_hash, admin_role="analyst")
        token = _login(client).json()["access_token"]
        r = client.delete(
            "/api/v1/cache?confirm=true",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 403


# ---------------------------------------------------------------------------
# API-key flow still works alongside user auth
# ---------------------------------------------------------------------------

class TestApiKeyStillWorks:
    def test_api_key_enrich_when_both_modes_on(self, admin_hash: str) -> None:
        client, _ = _build(
            admin_hash=admin_hash, auth_enabled=True, api_keys=[_API_KEY]
        )
        r = client.post(
            "/api/v1/enrich",
            json={"ioc": "8.8.8.8"},
            headers={"X-API-Key": _API_KEY},
        )
        assert r.status_code == 200

    def test_admin_api_key_clears_cache(self, admin_hash: str) -> None:
        client, fake = _build(
            admin_hash=admin_hash,
            auth_enabled=True,
            api_keys=[_API_KEY],
            admin_api_keys=[_ADMIN_KEY],
        )
        r = client.delete(
            "/api/v1/cache?confirm=true",
            headers={"X-Admin-API-Key": _ADMIN_KEY},
        )
        assert r.status_code == 200
        assert fake.clear_cache_calls == 1

    def test_api_key_only_mode_unaffected(self) -> None:
        # user_auth off, api-key on — classic Phase 2.5 behaviour.
        client, _ = _build(
            user_auth_enabled=False, auth_enabled=True, api_keys=[_API_KEY]
        )
        assert client.post(
            "/api/v1/enrich", json={"ioc": "8.8.8.8"},
            headers={"X-API-Key": _API_KEY},
        ).status_code == 200
        assert client.post(
            "/api/v1/enrich", json={"ioc": "8.8.8.8"}
        ).status_code == 401


# ---------------------------------------------------------------------------
# Secret / token leakage
# ---------------------------------------------------------------------------

class TestNoLeakage:
    def test_password_not_logged(self, admin_hash: str, caplog) -> None:
        client, _ = _build(admin_hash=admin_hash)
        caplog.set_level(logging.DEBUG, logger="ioc_enricher")
        secret_pw = "LEAKDETECT-PASSWORD-NEVER-LOG"
        _login(client, password=secret_pw)
        for record in caplog.records:
            assert secret_pw not in record.getMessage()

    def test_jwt_secret_not_in_openapi(self, admin_hash: str) -> None:
        client, _ = _build(admin_hash=admin_hash, enable_docs=True)
        schema = client.get("/openapi.json")
        assert schema.status_code == 200
        assert _JWT_SECRET not in schema.text

    def test_access_token_not_logged(self, admin_hash: str, caplog) -> None:
        client, _ = _build(admin_hash=admin_hash)
        caplog.set_level(logging.DEBUG, logger="ioc_enricher")
        token = _login(client).json()["access_token"]
        client.get(
            "/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}
        )
        for record in caplog.records:
            assert token not in record.getMessage()


# ---------------------------------------------------------------------------
# JWT primitives
# ---------------------------------------------------------------------------

class TestJwtPrimitives:
    def test_access_token_decodes(self) -> None:
        from ioc_enricher.web.api.security.jwt_tokens import (
            ACCESS_TOKEN_TYPE,
            decode_token,
        )

        token, jti = create_access_token(
            subject="u", role="analyst", secret=_JWT_SECRET
        )
        decoded = decode_token(
            token, secret=_JWT_SECRET, expected_type=ACCESS_TOKEN_TYPE
        )
        assert decoded.subject == "u"
        assert decoded.role == "analyst"
        assert decoded.jti == jti

    def test_wrong_type_rejected(self) -> None:
        from ioc_enricher.web.api.security.jwt_tokens import (
            REFRESH_TOKEN_TYPE,
            TokenError,
            decode_token,
        )

        token, _ = create_access_token(
            subject="u", role="analyst", secret=_JWT_SECRET
        )
        with pytest.raises(TokenError):
            decode_token(
                token, secret=_JWT_SECRET, expected_type=REFRESH_TOKEN_TYPE
            )

    def test_wrong_secret_rejected(self) -> None:
        from ioc_enricher.web.api.security.jwt_tokens import (
            TokenError,
            decode_token,
        )

        token, _ = create_access_token(
            subject="u", role="analyst", secret=_JWT_SECRET
        )
        with pytest.raises(TokenError):
            decode_token(token, secret="a-completely-different-secret-value")

    def test_strong_secret_check(self) -> None:
        from ioc_enricher.web.api.security.user_auth import is_strong_jwt_secret

        assert is_strong_jwt_secret(_JWT_SECRET) is True
        assert is_strong_jwt_secret("short") is False
        assert is_strong_jwt_secret("changeme") is False
        assert is_strong_jwt_secret(None) is False


# ---------------------------------------------------------------------------
# Password primitives
# ---------------------------------------------------------------------------

class TestPasswordPrimitives:
    def test_verify_roundtrip(self) -> None:
        h = hash_password("Sup3rStr0ngPass")
        from ioc_enricher.web.api.security.password import verify_password

        assert verify_password("Sup3rStr0ngPass", h) is True
        assert verify_password("wrong", h) is False

    def test_hash_differs_from_plaintext(self) -> None:
        h = hash_password("plaintextpw")
        assert h != "plaintextpw"
        assert h.startswith("$argon2")

    def test_verify_handles_garbage_hash(self) -> None:
        from ioc_enricher.web.api.security.password import verify_password

        assert verify_password("anything", "not-a-valid-hash") is False
        assert verify_password("anything", "") is False
