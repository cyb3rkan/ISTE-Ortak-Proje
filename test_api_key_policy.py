"""
Configured API keys meet the same bar as the JWT signing secret.

Older documentation showed ``change-me-dev-api-key`` / ``change-me-dev-admin-key``
as API-key examples; a deployment that copied them had a public key. Now:

* documented placeholders and well-known weak values are refused in every
  mode, debug included;
* other weak keys (short, repetitive, sequential) are refused in debug mode
  and in production unless ``IOC_WEB_REQUIRE_STRONG_API_KEYS_IN_PROD=false``;
* a refused key authenticates nothing (fail closed); startup logs how many
  keys were ignored and why, never a key.

Keys are generated per run (``secrets.token_urlsafe``) or are documentation
placeholders — no realistic credential is written in this file.
"""
from __future__ import annotations

import logging
import secrets

import pytest
from fastapi.testclient import TestClient

from ioc_enricher.web.api.app import create_app
from ioc_enricher.web.api.deps import get_enrichment_service
from ioc_enricher.web.api.security.secret_strength import accepted_api_keys, api_key_problem
from ioc_enricher.web.settings import WebSettings

from ..conftest import FakeService

_STRONG = secrets.token_urlsafe(32)
_STRONG_ADMIN = secrets.token_urlsafe(32)
_DOC_PLACEHOLDERS = ["change-me-dev-api-key", "change-me-dev-admin-key", "your-api-key-here-example"]
_WEAK = ["short-key-1", "k" * 40, "abcdefghijklmnopqrstuvwxyz0123456789"]


def _build(**overrides) -> tuple[TestClient, FakeService]:
    fake = FakeService()
    base = dict(auth_enabled=True, rate_limit_enabled=False)
    base.update(overrides)
    app = create_app(WebSettings(**base))
    app.dependency_overrides[get_enrichment_service] = lambda: fake
    return TestClient(app, raise_server_exceptions=False), fake


def _enrich(client: TestClient, key: str):
    return client.post("/api/v1/enrich", json={"ioc": "203.0.113.7"}, headers={"X-API-Key": key})


class TestPlaceholderKeys:
    @pytest.mark.parametrize("key", _DOC_PLACEHOLDERS)
    @pytest.mark.parametrize("mode", [
        dict(debug=False), dict(debug=True), dict(debug=False, require_strong_api_keys_in_prod=False),
    ], ids=["production", "debug", "production-opt-out"])
    def test_documented_placeholders_never_authenticate(self, key, mode):
        client, fake = _build(api_keys=[key], **mode)
        assert _enrich(client, key).status_code == 403
        assert fake.enrich_calls == []

    @pytest.mark.parametrize("key", _DOC_PLACEHOLDERS)
    def test_placeholder_admin_key_never_clears_the_cache(self, key):
        client, fake = _build(api_keys=[_STRONG], admin_api_keys=[key])
        r = client.delete("/api/v1/cache?confirm=true", headers={"X-Admin-API-Key": key})
        assert r.status_code == 403
        assert fake.clear_cache_calls == 0


class TestWeakKeys:
    @pytest.mark.parametrize("key", _WEAK)
    def test_weak_keys_are_refused_in_production_by_default(self, key):
        client, fake = _build(api_keys=[key])
        assert _enrich(client, key).status_code == 403
        assert fake.enrich_calls == []

    @pytest.mark.parametrize("key", _WEAK)
    def test_debug_mode_is_held_to_the_same_bar(self, key):
        client, _ = _build(api_keys=[key], debug=True, require_strong_api_keys_in_prod=False)
        assert _enrich(client, key).status_code == 403

    @pytest.mark.parametrize("key", _WEAK)
    def test_explicit_production_opt_out_accepts_a_weak_key(self, key):
        client, _ = _build(api_keys=[key], require_strong_api_keys_in_prod=False)
        assert _enrich(client, key).status_code == 200


class TestStrongKeys:
    def test_generated_keys_authenticate(self):
        client, fake = _build(api_keys=[_STRONG], admin_api_keys=[_STRONG_ADMIN])
        assert _enrich(client, _STRONG).status_code == 200
        r = client.delete("/api/v1/cache?confirm=true", headers={"X-Admin-API-Key": _STRONG_ADMIN})
        assert r.status_code == 200
        assert fake.clear_cache_calls == 1

    def test_a_weak_key_next_to_a_strong_one_only_disables_itself(self):
        client, _ = _build(api_keys=["short-key-1", _STRONG])
        assert _enrich(client, "short-key-1").status_code == 403
        assert _enrich(client, _STRONG).status_code == 200

    @pytest.mark.parametrize("generated", [secrets.token_urlsafe(32), secrets.token_hex(32),
                                           secrets.token_urlsafe(24)])
    def test_documented_generators_pass(self, generated):
        assert api_key_problem(generated, WebSettings()) is None


class TestPolicyHelpers:
    def test_problems_are_named(self):
        assert api_key_problem("change-me-dev-api-key", WebSettings()) == "placeholder"
        assert api_key_problem("short-key-1", WebSettings()) == "weak"
        relaxed = WebSettings(require_strong_api_keys_in_prod=False)
        assert api_key_problem("short-key-1", relaxed) is None

    def test_accepted_keys_keep_order_and_drop_refused_ones(self):
        keys = [_STRONG, "dev", _STRONG_ADMIN]
        assert accepted_api_keys(keys, WebSettings()) == [_STRONG, _STRONG_ADMIN]


class TestStartupLog:
    def test_refused_keys_are_counted_never_printed(self, caplog):
        with caplog.at_level(logging.WARNING, logger="ioc_enricher.web.auth"):
            _build(api_keys=["change-me-dev-api-key", "short-key-1", _STRONG],
                   admin_api_keys=["change-me-dev-admin-key"])
        text = caplog.text
        assert "api-key-rejected" in text
        assert "2 of 3 API key(s)" in text and "1 of 1 admin key(s)" in text
        for value in ("change-me-dev-api-key", "short-key-1", _STRONG, "change-me-dev-admin-key"):
            assert value not in text

    def test_nothing_is_logged_for_good_keys(self, caplog):
        with caplog.at_level(logging.WARNING, logger="ioc_enricher.web.auth"):
            _build(api_keys=[_STRONG], admin_api_keys=[_STRONG_ADMIN])
        assert "api-key-rejected" not in caplog.text


class TestEnvironment:
    @pytest.mark.parametrize("raw, expected", [(None, True), ("true", True), ("false", False)])
    def test_opt_out_is_read_from_the_environment(self, monkeypatch, raw, expected):
        from ioc_enricher.web.settings import load_settings
        if raw is None:
            monkeypatch.delenv("IOC_WEB_REQUIRE_STRONG_API_KEYS_IN_PROD", raising=False)
        else:
            monkeypatch.setenv("IOC_WEB_REQUIRE_STRONG_API_KEYS_IN_PROD", raw)
        assert load_settings().require_strong_api_keys_in_prod is expected
