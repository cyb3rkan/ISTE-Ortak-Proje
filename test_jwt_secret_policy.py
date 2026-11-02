"""
Regression tests for G-1: documented placeholders and other guessable values
are never accepted as the JWT signing secret.

Before the fix the strength check was "at least 32 characters and not one of
eight exact words", so the placeholders shipped in ``.env.example`` and
``docker/README.md`` passed it. A deployment that kept a placeholder signed
its tokens with a key anyone reading the docs could use to mint an admin
token.

Debug mode also used to skip the length and diversity rules, so a short or
patterned private secret (``local-dev-only``, ``aaaa…``) signed valid tokens
there. It now meets the same bar as production, and sequential or
keyboard-row values (``abcd…``, ``qwerty…``) are refused in every mode.

Secret values never reach the test output: every parameter has a neutral id
and no assertion expression contains the value itself.
"""
from __future__ import annotations

import logging
import random
import secrets
import string

import pytest
from fastapi.testclient import TestClient

from ioc_enricher.web.api.app import create_app
from ioc_enricher.web.api.deps import get_enrichment_service
from ioc_enricher.web.api.security.jwt_tokens import create_access_token
from ioc_enricher.web.api.security.user_auth import (
    AuthConfigError,
    assert_jwt_secret_usable,
    is_strong_jwt_secret,
    log_auth_config_problems,
)
from ioc_enricher.web.settings import WebSettings

from ..conftest import FakeService

# Shipped verbatim in .env.example and docker/README.md until Phase 2, so
# configurations copied from those docs may still carry them.
_DOCUMENTED_PLACEHOLDERS = [
    pytest.param("REPLACE_WITH_STRONG_SECRET_MIN_48_CHARS", id="env-example"),
    pytest.param("replace-with-a-strong-random-secret", id="docker-readme"),
]

# Other placeholder-shaped values, each at least 32 characters long.
_PLACEHOLDER_SHAPED = [
    pytest.param("please-change-me-before-going-to-production", id="change-me"),
    pytest.param("your-jwt-signing-secret-goes-here-0123456789", id="secret-goes-here"),
    pytest.param("example-jwt-key-for-the-documentation-only-01", id="example"),
    pytest.param("insert-a-long-random-value-here-before-deploying", id="insert-here"),
    pytest.param("default-signing-key-value-0000000000000000000", id="default"),
    pytest.param("generate-one-with-openssl-rand-base64-48-bytes", id="generate-hint"),
]

# Short, publicly known weak values.
_KNOWN_WEAK = [
    pytest.param("dev", id="dev"),
    pytest.param("changeme", id="changeme"),
    pytest.param("secret", id="secret"),
    pytest.param("devsecret", id="devsecret"),
]

# Long enough, but trivially guessable.
_LOW_DIVERSITY = [
    pytest.param("a" * 48, id="one-char"),
    pytest.param("x7" + "a" * 40, id="mostly-one-char"),
    pytest.param("0123456789" * 4, id="repeated-digits"),
    pytest.param("Ab1-Cd2_" * 5, id="repeated-block"),
]

# Long and varied, but typed along the alphabet, the digits or a keyboard row.
_SEQUENTIAL = [
    pytest.param("abcdefghijklmnopqrstuvwxyz012345", id="alphabet-run"),
    pytest.param("zyxwvutsrqponmlkjihgfedcba987654", id="reverse-run"),
    pytest.param("qwertyuiopasdfghjklzxcvbnm123456", id="keyboard-rows"),
    pytest.param("AbCdEfGhIjKlMnOpQrStUvWxYz0123456789", id="mixed-case-run"),
]

# Not a placeholder, but far shorter than a generated secret.
_SHORT_PRIVATE = [
    pytest.param("local-dev-only", id="short-phrase"),
    pytest.param("k9#Vq2!m", id="short-mixed"),
    pytest.param("zq", id="tiny"),
]

_URLSAFE_ALPHABET = string.ascii_letters + string.digits + "-_"


def _seeded_urlsafe(seed: int) -> str:
    """Reproducible stand-in for ``secrets.token_urlsafe(48)``."""
    return "".join(random.Random(seed).choices(_URLSAFE_ALPHABET, k=64))


_GENERATED = [
    pytest.param(secrets.token_hex(32), id="token-hex-32"),
    pytest.param(_seeded_urlsafe(11), id="urlsafe-seed-11"),
    pytest.param(_seeded_urlsafe(22), id="urlsafe-seed-22"),
    pytest.param(_seeded_urlsafe(33), id="urlsafe-seed-33"),
]

_MODES = [
    pytest.param({}, id="production"),
    pytest.param({"debug": True}, id="debug"),
    pytest.param({"require_strong_jwt_secret_in_prod": False}, id="strength-check-off"),
]


def _settings(secret: str, **overrides) -> WebSettings:
    base = dict(
        user_auth_enabled=True,
        jwt_secret_key=secret,
        debug=False,
        rate_limit_enabled=False,
    )
    base.update(overrides)
    return WebSettings(**base)


class TestStrengthCheck:
    @pytest.mark.parametrize("value", _DOCUMENTED_PLACEHOLDERS + _PLACEHOLDER_SHAPED)
    def test_placeholder_is_not_strong(self, value: str) -> None:
        accepted = is_strong_jwt_secret(value)
        assert accepted is False

    @pytest.mark.parametrize("value", _LOW_DIVERSITY)
    def test_low_diversity_is_not_strong(self, value: str) -> None:
        accepted = is_strong_jwt_secret(value)
        assert accepted is False

    @pytest.mark.parametrize("value", _SEQUENTIAL)
    def test_sequential_is_not_strong(self, value: str) -> None:
        accepted = is_strong_jwt_secret(value)
        assert accepted is False

    @pytest.mark.parametrize("value", _GENERATED)
    def test_generated_secret_is_strong(self, value: str) -> None:
        accepted = is_strong_jwt_secret(value)
        assert accepted is True


class TestConfigRejectsGuessableSecrets:
    @pytest.mark.parametrize("mode", _MODES)
    @pytest.mark.parametrize(
        "value", _DOCUMENTED_PLACEHOLDERS + _PLACEHOLDER_SHAPED + _KNOWN_WEAK
    )
    def test_publicly_known_secret_rejected_in_every_mode(
        self, value: str, mode: dict
    ) -> None:
        with pytest.raises(AuthConfigError):
            assert_jwt_secret_usable(_settings(value, **mode))

    @pytest.mark.parametrize("value", _DOCUMENTED_PLACEHOLDERS + _LOW_DIVERSITY)
    def test_rejection_message_does_not_echo_secret(self, value: str) -> None:
        with pytest.raises(AuthConfigError) as excinfo:
            assert_jwt_secret_usable(_settings(value))
        leaked = value in str(excinfo.value)
        assert not leaked

    @pytest.mark.parametrize("value", _GENERATED)
    def test_generated_secret_is_usable(self, value: str) -> None:
        usable = assert_jwt_secret_usable(_settings(value)) == value
        assert usable


_GUESSABLE_PRIVATE = _SHORT_PRIVATE + _LOW_DIVERSITY + _SEQUENTIAL


class TestDebugModeUsesTheSameBar:
    @pytest.mark.parametrize("value", _GUESSABLE_PRIVATE)
    def test_guessable_secret_rejected_in_debug(self, value: str) -> None:
        with pytest.raises(AuthConfigError):
            assert_jwt_secret_usable(_settings(value, debug=True))

    @pytest.mark.parametrize("value", _GUESSABLE_PRIVATE)
    def test_debug_rejection_message_does_not_echo_secret(self, value: str) -> None:
        with pytest.raises(AuthConfigError) as excinfo:
            assert_jwt_secret_usable(_settings(value, debug=True))
        leaked = value in str(excinfo.value)
        assert not leaked

    @pytest.mark.parametrize("value", _GENERATED)
    def test_generated_secret_usable_in_debug(self, value: str) -> None:
        usable = assert_jwt_secret_usable(_settings(value, debug=True)) == value
        assert usable

    def test_production_opt_out_does_not_relax_debug(self) -> None:
        settings = _settings(
            "local-dev-only", debug=True, require_strong_jwt_secret_in_prod=False
        )
        with pytest.raises(AuthConfigError):
            assert_jwt_secret_usable(settings)

    @pytest.mark.parametrize("value", _SHORT_PRIVATE)
    def test_debug_app_refuses_login_and_forged_tokens(self, value: str) -> None:
        fake = FakeService()
        app = create_app(_settings(value, debug=True))
        app.dependency_overrides[get_enrichment_service] = lambda: fake
        client = TestClient(app, raise_server_exceptions=False)
        forged, _ = create_access_token(subject="attacker", role="admin", secret=value)

        r = client.post(
            "/api/v1/enrich",
            json={"ioc": "8.8.8.8"},
            headers={"Authorization": f"Bearer {forged}"},
        )
        assert r.status_code == 401
        assert fake.enrich_calls == []
        login = client.post(
            "/api/v1/auth/login", json={"username": "admin", "password": "x"}
        )
        assert login.status_code == 503


class TestNoSecretInLogs:
    @pytest.mark.parametrize("value", _DOCUMENTED_PLACEHOLDERS)
    def test_startup_flags_placeholder_without_logging_it(
        self, value: str, caplog
    ) -> None:
        with caplog.at_level(logging.DEBUG, logger="ioc_enricher"):
            usable = log_auth_config_problems(_settings(value))
        assert usable is False
        assert "auth-misconfigured" in caplog.text
        leaked = value in caplog.text
        assert not leaked


class TestForgedTokenWithPlaceholderSecret:
    @pytest.mark.parametrize("value", _DOCUMENTED_PLACEHOLDERS)
    def test_token_signed_with_placeholder_grants_nothing(self, value: str) -> None:
        fake = FakeService()
        app = create_app(_settings(value))
        app.dependency_overrides[get_enrichment_service] = lambda: fake
        client = TestClient(app, raise_server_exceptions=False)
        forged, _ = create_access_token(subject="attacker", role="admin", secret=value)
        headers = {"Authorization": f"Bearer {forged}"}

        assert client.get("/api/v1/providers", headers=headers).status_code == 401
        assert client.get("/api/v1/auth/me", headers=headers).status_code == 401
        cleared = client.delete("/api/v1/cache?confirm=true", headers=headers)
        assert cleared.status_code in (401, 403)
        assert fake.clear_cache_calls == 0
        login = client.post(
            "/api/v1/auth/login", json={"username": "admin", "password": "x"}
        )
        assert login.status_code == 503
