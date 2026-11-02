"""
End-to-end tests for the Phase 2.5 API-key auth layer.

Covers:

* No auth mode configured — protected routes fail closed (503), admin 403
  (the full matrix is in ``test_auth_secure_defaults.py``).
* 401 when a key is required but absent.
* 403 when a key is presented but invalid or under-scoped.
* Admin endpoint scoping (normal key cannot escalate to admin).
* Public ``/health`` behaviour under both ``allow_health_without_auth`` values.
* Constant-time comparison helper.
* HSTS opt-in.
* Secret-leakage tests for log output, response bodies and OpenAPI.
"""
from __future__ import annotations

import secrets

import logging

import pytest
from fastapi import Request
from fastapi.testclient import TestClient

from ioc_enricher.web.api.app import create_app
from ioc_enricher.web.api.deps import get_enrichment_service
from ioc_enricher.web.api.security.auth import (
    AuthForbiddenError,
    AuthRequiredError,
    compare_api_key,
    match_api_key,
)
from ioc_enricher.web.api.security.policies import (
    _extract_header,
    optional_api_key,
    require_admin_api_key,
    require_api_key,
)
from ioc_enricher.web.settings import WebSettings

from ..conftest import FakeService


_API_KEY = "test-api-key-" + secrets.token_urlsafe(24)
_ADMIN_KEY = "test-admin-key-" + secrets.token_urlsafe(24)


def _build(
    *,
    auth_enabled: bool = False,
    api_keys=None,
    admin_api_keys=None,
    allow_health_without_auth: bool = True,
    hsts_enabled: bool = False,
    enable_docs: bool | None = None,
    fake_service: FakeService | None = None,
) -> tuple[TestClient, FakeService]:
    fake = fake_service or FakeService()
    settings = WebSettings(
        auth_enabled=auth_enabled,
        api_keys=list(api_keys or []),
        admin_api_keys=list(admin_api_keys or []),
        allow_health_without_auth=allow_health_without_auth,
        hsts_enabled=hsts_enabled,
        enable_docs=enable_docs,
        rate_limit_enabled=False,
    )
    app = create_app(settings)
    app.dependency_overrides[get_enrichment_service] = lambda: fake
    return TestClient(app, raise_server_exceptions=False), fake


# ---------------------------------------------------------------------------
# No auth mode configured (the default) — fails closed
# ---------------------------------------------------------------------------

class TestAuthDisabled:
    def test_enrich_closed_without_any_auth_mode(self) -> None:
        client, fake = _build(auth_enabled=False)
        r = client.post("/api/v1/enrich", json={"ioc": "8.8.8.8"})
        assert r.status_code == 503
        assert fake.enrich_calls == []

    def test_delete_cache_closed_before_confirm_check(self) -> None:
        client, _ = _build(auth_enabled=False)
        r = client.delete("/api/v1/cache")
        assert r.status_code == 403

    def test_delete_cache_with_confirm_still_closed(self) -> None:
        client, fake = _build(auth_enabled=False)
        r = client.delete("/api/v1/cache?confirm=true")
        assert r.status_code == 403
        assert fake.clear_cache_calls == 0


# ---------------------------------------------------------------------------
# Auth enabled — missing key
# ---------------------------------------------------------------------------

class TestMissingKey:
    @pytest.mark.parametrize(
        "method,path,body",
        [
            ("post", "/api/v1/enrich", {"ioc": "8.8.8.8"}),
            ("post", "/api/v1/enrich/batch", {"iocs": ["8.8.8.8"]}),
            ("get", "/api/v1/providers", None),
            ("get", "/api/v1/cache", None),
            (
                "get",
                "/api/v1/reports/11111111-1111-4111-8111-111111111111",
                None,
            ),
        ],
    )
    def test_returns_401(self, method: str, path: str, body) -> None:
        client, _ = _build(auth_enabled=True, api_keys=[_API_KEY])
        fn = getattr(client, method)
        r = fn(path) if body is None else fn(path, json=body)
        assert r.status_code == 401, r.text
        problem = r.json()
        assert problem["status"] == 401
        assert problem["title"] == "Authentication required"
        # RFC 7235: 401 must advertise the auth scheme.
        assert "ApiKey" in r.headers.get("www-authenticate", "")


# ---------------------------------------------------------------------------
# Auth enabled — invalid key
# ---------------------------------------------------------------------------

class TestInvalidKey:
    def test_returns_403_and_no_key_in_body(self) -> None:
        client, _ = _build(auth_enabled=True, api_keys=[_API_KEY])
        evil_key = "evil-key-attempt-XYZ-LEAKDETECT-9999"
        r = client.post(
            "/api/v1/enrich",
            json={"ioc": "8.8.8.8"},
            headers={"X-API-Key": evil_key},
        )
        assert r.status_code == 403
        body = r.json()
        assert body["status"] == 403
        assert body["title"] == "Forbidden"
        # The candidate must never echo back.
        assert evil_key not in r.text

    def test_normal_key_cannot_unlock_admin(self) -> None:
        client, _ = _build(
            auth_enabled=True,
            api_keys=[_API_KEY],
            admin_api_keys=[_ADMIN_KEY],
        )
        # Even posting the *normal* key on the X-API-Key header doesn't pass
        # the admin gate — the admin endpoint reads a different header.
        r = client.delete(
            "/api/v1/cache?confirm=true",
            headers={"X-API-Key": _API_KEY},
        )
        assert r.status_code == 401

    def test_invalid_admin_key_403(self) -> None:
        client, _ = _build(
            auth_enabled=True,
            api_keys=[_API_KEY],
            admin_api_keys=[_ADMIN_KEY],
        )
        r = client.delete(
            "/api/v1/cache?confirm=true",
            headers={"X-Admin-API-Key": "nope"},
        )
        assert r.status_code == 403

    def test_admin_unconfigured_fails_closed(self) -> None:
        client, _ = _build(auth_enabled=True, api_keys=[_API_KEY])  # no admin keys
        r = client.delete(
            "/api/v1/cache?confirm=true",
            headers={"X-Admin-API-Key": "anything"},
        )
        assert r.status_code == 403
        body = r.json()
        assert "not configured" in body["detail"].lower()


# ---------------------------------------------------------------------------
# Auth enabled — valid key
# ---------------------------------------------------------------------------

class TestValidKey:
    def test_protected_endpoints_pass(self) -> None:
        client, _ = _build(auth_enabled=True, api_keys=[_API_KEY])
        h = {"X-API-Key": _API_KEY}
        assert client.post("/api/v1/enrich", json={"ioc": "8.8.8.8"}, headers=h).status_code == 200
        assert client.post("/api/v1/enrich/batch", json={"iocs": ["1.1.1.1"]}, headers=h).status_code == 200
        assert client.get("/api/v1/providers", headers=h).status_code == 200
        assert client.get("/api/v1/cache", headers=h).status_code == 200

    def test_admin_key_clears_cache(self) -> None:
        client, fake = _build(
            auth_enabled=True,
            api_keys=[_API_KEY],
            admin_api_keys=[_ADMIN_KEY],
        )
        r = client.delete(
            "/api/v1/cache?confirm=true",
            headers={"X-Admin-API-Key": _ADMIN_KEY},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["cleared"] is True
        assert fake.clear_cache_calls == 1

    def test_admin_without_confirm_is_still_400(self) -> None:
        client, _ = _build(
            auth_enabled=True,
            api_keys=[_API_KEY],
            admin_api_keys=[_ADMIN_KEY],
        )
        r = client.delete(
            "/api/v1/cache",
            headers={"X-Admin-API-Key": _ADMIN_KEY},
        )
        assert r.status_code == 400


# ---------------------------------------------------------------------------
# Public health behaviour
# ---------------------------------------------------------------------------

class TestHealthGate:
    def test_health_public_by_default(self) -> None:
        client, _ = _build(auth_enabled=True, api_keys=[_API_KEY])
        assert client.get("/api/v1/health").status_code == 200

    def test_health_locked_when_configured(self) -> None:
        client, _ = _build(
            auth_enabled=True,
            api_keys=[_API_KEY],
            allow_health_without_auth=False,
        )
        assert client.get("/api/v1/health").status_code == 401
        ok = client.get("/api/v1/health", headers={"X-API-Key": _API_KEY})
        assert ok.status_code == 200


# ---------------------------------------------------------------------------
# Secret leakage
# ---------------------------------------------------------------------------

class TestSecretLeakage:
    def test_invalid_key_value_not_logged(self, caplog) -> None:
        client, _ = _build(auth_enabled=True, api_keys=[_API_KEY])
        secret_attempt = "LEAKDETECT-SHOULD-NEVER-APPEAR"
        caplog.set_level(logging.DEBUG, logger="ioc_enricher")
        r = client.post(
            "/api/v1/enrich",
            json={"ioc": "8.8.8.8"},
            headers={"X-API-Key": secret_attempt},
        )
        assert r.status_code == 403
        for record in caplog.records:
            assert secret_attempt not in record.getMessage()

    def test_configured_key_not_in_openapi(self) -> None:
        client, _ = _build(auth_enabled=True, api_keys=[_API_KEY], enable_docs=True)
        schema = client.get("/openapi.json")
        assert schema.status_code == 200
        assert _API_KEY not in schema.text

    def test_configured_admin_key_not_in_openapi(self) -> None:
        client, _ = _build(
            auth_enabled=True,
            api_keys=[_API_KEY],
            admin_api_keys=[_ADMIN_KEY],
            enable_docs=True,
        )
        schema = client.get("/openapi.json")
        assert schema.status_code == 200
        assert _ADMIN_KEY not in schema.text


# ---------------------------------------------------------------------------
# Constant-time helper
# ---------------------------------------------------------------------------

class TestCompareApiKey:
    def test_equal_strings_match(self) -> None:
        assert compare_api_key("abc123", "abc123") is True

    def test_unequal_strings_differ(self) -> None:
        assert compare_api_key("abc123", "abc124") is False

    def test_empty_is_false(self) -> None:
        assert compare_api_key("", "anything") is False
        assert compare_api_key("anything", "") is False
        assert compare_api_key("", "") is False

    def test_none_is_false(self) -> None:
        assert compare_api_key(None, "anything") is False
        assert compare_api_key("anything", None) is False

    def test_different_lengths_handled(self) -> None:
        assert compare_api_key("short", "muchlongerkey") is False


class TestMatchApiKey:
    def test_present(self) -> None:
        assert match_api_key("b", ["a", "b", "c"]) is True

    def test_absent(self) -> None:
        assert match_api_key("x", ["a", "b", "c"]) is False

    def test_empty_candidate(self) -> None:
        assert match_api_key("", ["a", "b"]) is False
        assert match_api_key(None, ["a", "b"]) is False

    def test_empty_known(self) -> None:
        assert match_api_key("a", []) is False


# ---------------------------------------------------------------------------
# Direct dependency policy branches
# ---------------------------------------------------------------------------

def _request(headers: list[tuple[bytes, bytes]] | None = None) -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "scheme": "http",
            "path": "/api/v1/cache",
            "query_string": b"",
            "headers": headers or [],
            "client": ("127.0.0.1", 50000),
            "server": ("testserver", 80),
        }
    )


class TestPolicyDependencies:
    def test_extract_header_strips_value_and_rejects_newlines(self) -> None:
        assert _extract_header(_request([(b"x-api-key", b"  known  ")]), "X-API-Key") == "known"
        assert _extract_header(_request([(b"x-api-key", b"bad\nvalue")]), "X-API-Key") is None

    def test_api_dependency_accepts_valid_and_rejects_missing_or_invalid(self) -> None:
        settings = WebSettings(auth_enabled=True, api_keys=[_API_KEY], rate_limit_enabled=False)
        principal = require_api_key(_request([(b"x-api-key", _API_KEY.encode())]), settings)
        assert principal.scope == "api"
        with pytest.raises(AuthRequiredError):
            require_api_key(_request(), settings)
        with pytest.raises(AuthForbiddenError):
            require_api_key(_request([(b"x-api-key", b"invalid")]), settings)

    def test_admin_dependency_fails_closed_without_keys_and_accepts_admin_key(self) -> None:
        unconfigured = WebSettings(auth_enabled=True, rate_limit_enabled=False)
        with pytest.raises(AuthForbiddenError):
            require_admin_api_key(_request(), unconfigured)
        settings = WebSettings(auth_enabled=True, admin_api_keys=[_ADMIN_KEY], rate_limit_enabled=False)
        principal = require_admin_api_key(_request([(b"x-admin-api-key", _ADMIN_KEY.encode())]), settings)
        assert principal.scope == "admin"

    def test_optional_dependency_returns_authenticated_or_anonymous_principal(self) -> None:
        settings = WebSettings(auth_enabled=True, api_keys=[_API_KEY], rate_limit_enabled=False)
        assert optional_api_key(_request([(b"x-api-key", _API_KEY.encode())]), settings).scope == "api"
        assert optional_api_key(_request([(b"x-api-key", b"invalid")]), settings).scope == "public"


# ---------------------------------------------------------------------------
# HSTS
# ---------------------------------------------------------------------------

class TestHSTS:
    def test_off_by_default(self) -> None:
        client, _ = _build(hsts_enabled=False)
        r = client.get("/api/v1/health")
        assert "strict-transport-security" not in {k.lower() for k in r.headers}

    def test_on_when_configured(self) -> None:
        client, _ = _build(hsts_enabled=True)
        r = client.get("/api/v1/health")
        hsts = r.headers.get("strict-transport-security", "")
        assert "max-age=" in hsts
        assert "includeSubDomains" in hsts
