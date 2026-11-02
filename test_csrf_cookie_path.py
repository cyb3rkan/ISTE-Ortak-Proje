"""
Regression tests: the double-submit CSRF cookie must be readable by the SPA.

The CSRF cookie used to share the refresh cookie's narrow path
(``/api/v1/auth``). Browsers only expose a cookie to ``document.cookie`` when
its path matches the *page* URL, so JavaScript running on ``/analyze`` could
never read it: every silent refresh after a page reload was rejected with 403
(user logged out) and UI logout could not revoke the refresh token.

The refresh token itself must stay httpOnly and scoped to the auth routes.
"""
from __future__ import annotations

import secrets

import pytest
from fastapi.testclient import TestClient

from ioc_enricher.web.api.app import create_app
from ioc_enricher.web.api.deps import get_enrichment_service
from ioc_enricher.web.api.security.password import hash_password
from ioc_enricher.web.settings import WebSettings, load_settings

from ..conftest import FakeService

_SECRET = secrets.token_hex(32)
_PASS = "AdminStrongPass123"


@pytest.fixture(scope="module")
def admin_hash() -> str:
    return hash_password(_PASS)


def _client(admin_hash: str) -> TestClient:
    app = create_app(
        WebSettings(
            user_auth_enabled=True,
            jwt_secret_key=_SECRET,
            bootstrap_admin_username="admin",
            bootstrap_admin_password_hash=admin_hash,
            rate_limit_enabled=False,
        )
    )
    app.dependency_overrides[get_enrichment_service] = lambda: FakeService()
    return TestClient(app, raise_server_exceptions=False)


def _set_cookies(response) -> list[str]:
    return [c.lower() for c in response.headers.get_list("set-cookie")]


def _cookie(headers: list[str], name: str, *, deleting: bool = False) -> str:
    for c in headers:
        is_delete = "max-age=0" in c or 'expires=thu, 01 jan 1970' in c
        if c.startswith(f"{name}=") and is_delete == deleting:
            return c
    raise AssertionError(f"no {'deletion of' if deleting else ''} {name} in {headers}")


class TestCookiePaths:
    def test_csrf_cookie_is_site_wide(self, admin_hash: str) -> None:
        r = _client(admin_hash).post(
            "/api/v1/auth/login", json={"username": "admin", "password": _PASS}
        )
        csrf = _cookie(_set_cookies(r), "ioc_csrf_token")
        assert "path=/;" in csrf + ";"
        assert "httponly" not in csrf

    def test_refresh_cookie_stays_narrow_and_httponly(self, admin_hash: str) -> None:
        r = _client(admin_hash).post(
            "/api/v1/auth/login", json={"username": "admin", "password": _PASS}
        )
        refresh = _cookie(_set_cookies(r), "ioc_refresh_token")
        assert "path=/api/v1/auth" in refresh
        assert "httponly" in refresh

    def test_login_clears_legacy_narrow_csrf_cookie(self, admin_hash: str) -> None:
        r = _client(admin_hash).post(
            "/api/v1/auth/login", json={"username": "admin", "password": _PASS}
        )
        legacy = _cookie(_set_cookies(r), "ioc_csrf_token", deleting=True)
        assert "path=/api/v1/auth" in legacy

    def test_logout_clears_csrf_cookie_at_both_paths(self, admin_hash: str) -> None:
        client = _client(admin_hash)
        client.post("/api/v1/auth/login", json={"username": "admin", "password": _PASS})
        csrf = client.cookies.get("ioc_csrf_token")
        r = client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": csrf})
        deletions = [
            c for c in _set_cookies(r)
            if c.startswith("ioc_csrf_token=") and ("max-age=0" in c or "1970" in c)
        ]
        paths = {seg.strip() for c in deletions for seg in c.split(";") if seg.strip().startswith("path=")}
        assert {"path=/", "path=/api/v1/auth"} <= paths

    def test_refresh_reissues_site_wide_csrf(self, admin_hash: str) -> None:
        client = _client(admin_hash)
        client.post("/api/v1/auth/login", json={"username": "admin", "password": _PASS})
        csrf = client.cookies.get("ioc_csrf_token")
        r = client.post("/api/v1/auth/refresh", headers={"X-CSRF-Token": csrf})
        assert r.status_code == 200
        assert "path=/;" in _cookie(_set_cookies(r), "ioc_csrf_token") + ";"

    def test_csrf_still_enforced(self, admin_hash: str) -> None:
        client = _client(admin_hash)
        client.post("/api/v1/auth/login", json={"username": "admin", "password": _PASS})
        assert client.post("/api/v1/auth/refresh").status_code == 403
        assert client.post(
            "/api/v1/auth/refresh", headers={"X-CSRF-Token": "forged"}
        ).status_code == 403


class TestSetting:
    def test_default_and_env(self, monkeypatch) -> None:
        monkeypatch.delenv("IOC_WEB_CSRF_COOKIE_PATH", raising=False)
        assert load_settings().csrf_cookie_path == "/"
        monkeypatch.setenv("IOC_WEB_CSRF_COOKIE_PATH", "/app")
        assert load_settings().csrf_cookie_path == "/app"
