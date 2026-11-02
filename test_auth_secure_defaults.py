"""
Regression tests for G-2: with no authentication mode configured, sensitive
and admin endpoints are closed instead of anonymously reachable.

Before the fix both auth modes defaulted to off, which made every endpoint
public — ``DELETE /cache`` included — and in debug mode not even the startup
warning was logged.

Endpoint decisions:

* ``/health`` is public by design and stays public. When an operator pins it
  to authentication it follows the protected-route rule below.
* ``/auth/*`` only exists with user auth enabled (404 otherwise, unchanged).
* Protected routes (enrich, batch, providers, cache stats, reports) answer
  503 when no auth mode is configured. The only way to serve them without
  credentials is the explicit development bypass, which requires debug mode
  and is refused at startup otherwise.
* Admin routes (``DELETE /cache``) never accept an anonymous request, in any
  configuration — the development bypass included.
"""
from __future__ import annotations

import logging
import secrets

import pytest
from fastapi import Request
from fastapi.testclient import TestClient

from ioc_enricher.web.api.app import create_app
from ioc_enricher.web.api.deps import get_enrichment_service
from ioc_enricher.web.api.security.auth import (
    AuthForbiddenError,
    AuthUnavailableError,
)
from ioc_enricher.web.api.security.policies import (
    require_admin_api_key,
    require_api_key,
)
from ioc_enricher.web.api.security.user_auth import AuthConfigError
from ioc_enricher.web.settings import WebSettings, load_settings

from ..conftest import FakeService

_API_KEY = "test-api-key-" + secrets.token_urlsafe(24)
_ADMIN_KEY = "test-admin-key-" + secrets.token_urlsafe(24)
_JWT_SECRET = secrets.token_hex(32)
_REPORT_ID = "11111111-1111-4111-8111-111111111111"
_DEV_BYPASS = {"debug": True, "dev_allow_unauthenticated": True}

# Every non-admin route guarded by require_api_key_or_user.
_PROTECTED = [
    pytest.param("post", "/api/v1/enrich", {"ioc": "8.8.8.8"}, id="enrich"),
    pytest.param("post", "/api/v1/enrich/batch", {"iocs": ["8.8.8.8"]}, id="enrich-batch"),
    pytest.param("get", "/api/v1/providers", None, id="providers"),
    pytest.param("get", "/api/v1/cache", None, id="cache-stats"),
    pytest.param("get", f"/api/v1/reports/{_REPORT_ID}", None, id="report"),
]


def _build(**overrides) -> tuple[TestClient, FakeService]:
    fake = FakeService()
    fake.add_report(_REPORT_ID, {"report_id": _REPORT_ID})
    app = create_app(WebSettings(rate_limit_enabled=False, **overrides))
    app.dependency_overrides[get_enrichment_service] = lambda: fake
    return TestClient(app, raise_server_exceptions=False), fake


def _call(client: TestClient, method: str, path: str, body):
    fn = getattr(client, method)
    return fn(path) if body is None else fn(path, json=body)


class TestNoAuthModeConfigured:
    @pytest.mark.parametrize("debug", [False, True], ids=["production", "debug"])
    @pytest.mark.parametrize("method, path, body", _PROTECTED)
    def test_protected_endpoint_fails_closed(
        self, method: str, path: str, body, debug: bool
    ) -> None:
        client, fake = _build(debug=debug)
        r = _call(client, method, path, body)
        assert r.status_code == 503
        assert r.json()["type"].endswith("/authentication-unavailable")
        assert fake.enrich_calls == []
        assert fake.batch_calls == []

    @pytest.mark.parametrize("debug", [False, True], ids=["production", "debug"])
    def test_admin_endpoint_fails_closed(self, debug: bool) -> None:
        client, fake = _build(debug=debug)
        r = client.delete("/api/v1/cache?confirm=true")
        assert r.status_code == 403
        assert "not configured" in r.json()["detail"].lower()
        assert fake.clear_cache_calls == 0

    def test_health_stays_public(self) -> None:
        client, _ = _build()
        assert client.get("/api/v1/health").status_code == 200

    def test_health_pinned_to_auth_fails_closed(self) -> None:
        client, _ = _build(allow_health_without_auth=False)
        assert client.get("/api/v1/health").status_code == 503

    def test_auth_routes_stay_absent(self) -> None:
        client, _ = _build()
        r = client.post("/api/v1/auth/login", json={"username": "a", "password": "b"})
        assert r.status_code == 404

    @pytest.mark.parametrize("debug", [False, True], ids=["production", "debug"])
    def test_startup_logs_the_closed_state(self, debug: bool, caplog) -> None:
        with caplog.at_level(logging.WARNING, logger="ioc_enricher.web.auth"):
            _build(debug=debug)
        assert "auth-not-configured" in caplog.text
        assert "auth-dev-bypass" not in caplog.text

    def test_bypass_is_off_by_default(self, monkeypatch) -> None:
        monkeypatch.delenv("IOC_WEB_DEV_ALLOW_UNAUTHENTICATED", raising=False)
        assert WebSettings().dev_allow_unauthenticated is False
        assert load_settings().dev_allow_unauthenticated is False


class TestDevelopmentBypass:
    @pytest.mark.parametrize("method, path, body", _PROTECTED)
    def test_opens_non_admin_endpoints_in_debug(self, method: str, path: str, body) -> None:
        client, _ = _build(**_DEV_BYPASS)
        assert _call(client, method, path, body).status_code == 200

    def test_admin_endpoint_stays_closed(self) -> None:
        client, fake = _build(**_DEV_BYPASS)
        r = client.delete("/api/v1/cache?confirm=true")
        assert r.status_code == 403
        assert fake.clear_cache_calls == 0

    @pytest.mark.parametrize(
        "extra",
        [
            pytest.param({}, id="no-auth"),
            pytest.param({"auth_enabled": True, "api_keys": [_API_KEY]}, id="api-key-auth"),
        ],
    )
    def test_refused_at_startup_outside_debug(self, extra: dict) -> None:
        with pytest.raises(AuthConfigError, match="IOC_WEB_DEV_ALLOW_UNAUTHENTICATED"):
            create_app(WebSettings(dev_allow_unauthenticated=True, **extra))

    def test_no_effect_once_an_auth_mode_is_enabled(self) -> None:
        client, _ = _build(auth_enabled=True, api_keys=[_API_KEY], **_DEV_BYPASS)
        anonymous = client.post("/api/v1/enrich", json={"ioc": "8.8.8.8"})
        assert anonymous.status_code == 401
        keyed = client.post(
            "/api/v1/enrich", json={"ioc": "8.8.8.8"}, headers={"X-API-Key": _API_KEY}
        )
        assert keyed.status_code == 200

    def test_startup_warns_loudly(self, caplog) -> None:
        with caplog.at_level(logging.WARNING, logger="ioc_enricher.web.auth"):
            _build(**_DEV_BYPASS)
        assert "auth-dev-bypass" in caplog.text
        assert "auth-not-configured" not in caplog.text

    @pytest.mark.parametrize(
        "raw, expected", [("true", True), ("1", True), ("false", False), ("", False)]
    )
    def test_read_from_env(self, monkeypatch, raw: str, expected: bool) -> None:
        monkeypatch.setenv("IOC_WEB_DEV_ALLOW_UNAUTHENTICATED", raw)
        assert load_settings().dev_allow_unauthenticated is expected


# Every way auth can be configured, the development bypass included.
_CONFIGURATIONS = [
    pytest.param({}, id="no-auth"),
    pytest.param({"debug": True}, id="no-auth-debug"),
    pytest.param(_DEV_BYPASS, id="dev-bypass"),
    pytest.param(
        {"auth_enabled": True, "api_keys": [_API_KEY]}, id="api-key-without-admin-keys"
    ),
    pytest.param(
        {"auth_enabled": True, "api_keys": [_API_KEY], "admin_api_keys": [_ADMIN_KEY]},
        id="api-key-with-admin-keys",
    ),
    pytest.param({"user_auth_enabled": True, "jwt_secret_key": _JWT_SECRET}, id="user-auth"),
    pytest.param({"user_auth_enabled": True}, id="user-auth-without-secret"),
    pytest.param(
        {
            "auth_enabled": True,
            "api_keys": [_API_KEY],
            "admin_api_keys": [_ADMIN_KEY],
            "user_auth_enabled": True,
            "jwt_secret_key": _JWT_SECRET,
        },
        id="both-modes",
    ),
    pytest.param(
        {**_DEV_BYPASS, "auth_enabled": True, "api_keys": [_API_KEY], "admin_api_keys": [_ADMIN_KEY]},
        id="dev-bypass-with-api-key-auth",
    ),
]


class TestAdminRouteNeverAnonymous:
    @pytest.mark.parametrize("config", _CONFIGURATIONS)
    def test_anonymous_clear_cache_rejected(self, config: dict) -> None:
        client, fake = _build(**config)
        r = client.delete("/api/v1/cache?confirm=true")
        assert r.status_code in (401, 403)
        assert fake.clear_cache_calls == 0

    @pytest.mark.parametrize("config", _CONFIGURATIONS)
    def test_regular_api_key_cannot_clear_cache(self, config: dict) -> None:
        client, fake = _build(**config)
        r = client.delete(
            "/api/v1/cache?confirm=true",
            headers={"X-API-Key": _API_KEY, "X-Admin-API-Key": _API_KEY},
        )
        assert r.status_code in (401, 403)
        assert fake.clear_cache_calls == 0


def _request() -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "scheme": "http",
            "path": "/api/v1/cache",
            "query_string": b"",
            "headers": [],
            "client": ("127.0.0.1", 50000),
            "server": ("testserver", 80),
        }
    )


class TestApiKeyOnlyDependencies:
    """The API-key-only dependencies follow the same rule when API-key auth is off."""

    @pytest.mark.parametrize(
        "config",
        [
            pytest.param({}, id="no-auth"),
            pytest.param({"user_auth_enabled": True, "jwt_secret_key": _JWT_SECRET}, id="user-auth-only"),
        ],
    )
    def test_require_api_key_fails_closed(self, config: dict) -> None:
        with pytest.raises(AuthUnavailableError):
            require_api_key(_request(), WebSettings(**config))

    def test_require_api_key_honours_the_dev_bypass(self) -> None:
        principal = require_api_key(_request(), WebSettings(**_DEV_BYPASS))
        assert principal.auth_type == "anonymous"

    @pytest.mark.parametrize(
        "config",
        [
            pytest.param({}, id="no-auth"),
            pytest.param(_DEV_BYPASS, id="dev-bypass"),
            pytest.param({"user_auth_enabled": True, "jwt_secret_key": _JWT_SECRET}, id="user-auth-only"),
        ],
    )
    def test_require_admin_api_key_never_anonymous(self, config: dict) -> None:
        with pytest.raises(AuthForbiddenError):
            require_admin_api_key(_request(), WebSettings(**config))
