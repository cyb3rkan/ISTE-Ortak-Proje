"""
Regression tests: the JWT secret / algorithm policy is enforced on *every*
path that verifies an access token, not only on the ``/auth/*`` routes.

Before the fix, ``/auth/login`` returned 503 for a weak secret in a
production-like deployment, but protected routes still accepted any access
token signed with that weak secret — so an attacker who guessed the secret
could forge an admin token.
"""
from __future__ import annotations

import logging
import secrets

import jwt
import pytest
from fastapi.testclient import TestClient

from ioc_enricher.web.api.app import create_app
from ioc_enricher.web.api.deps import get_enrichment_service
from ioc_enricher.web.api.security.jwt_tokens import create_access_token
from ioc_enricher.web.api.security.password import hash_password
from ioc_enricher.web.api.security.user_auth import (
    ALLOWED_JWT_ALGORITHMS,
    AuthConfigError,
    credential_fingerprint,
    resolve_jwt_config,
)
from ioc_enricher.web.settings import WebSettings

from ..conftest import FakeService

_STRONG_SECRET = secrets.token_hex(32)
_API_KEY = "test-api-key-" + secrets.token_urlsafe(24)

# Tokens are accepted only for the configured account and its current
# credential (see test_session_invalidation.py), so the "accepted" cases
# below configure one and mint tokens carrying its fingerprint.
_ADMIN_USER = "admin"
_ADMIN_HASH = hash_password(secrets.token_urlsafe(16))
_ACCOUNT = dict(bootstrap_admin_username=_ADMIN_USER, bootstrap_admin_password_hash=_ADMIN_HASH)
_FINGERPRINT = credential_fingerprint(WebSettings(**_ACCOUNT), _STRONG_SECRET)


def _account_token(*, algorithm: str = "HS256") -> str:
    token, _ = create_access_token(
        subject=_ADMIN_USER, role="admin", secret=_STRONG_SECRET,
        algorithm=algorithm, credential=_FINGERPRINT,
    )
    return token


def _build(**overrides) -> tuple[TestClient, FakeService]:
    fake = FakeService()
    base = dict(
        debug=False,
        user_auth_enabled=True,
        jwt_secret_key=_STRONG_SECRET,
        rate_limit_enabled=False,
    )
    base.update(overrides)
    app = create_app(WebSettings(**base))
    app.dependency_overrides[get_enrichment_service] = lambda: fake
    return TestClient(app, raise_server_exceptions=False), fake


def _forge(secret: str, *, role: str = "admin", algorithm: str = "HS256") -> str:
    token, _ = create_access_token(
        subject="attacker", role=role, secret=secret, algorithm=algorithm
    )
    return token


class TestWeakSecretCannotAuthenticate:
    @pytest.mark.parametrize("weak", ["dev", "short", "changeme"])
    def test_forged_token_rejected_on_enrich(self, weak: str) -> None:
        client, _ = _build(jwt_secret_key=weak)
        r = client.post(
            "/api/v1/enrich",
            json={"ioc": "8.8.8.8"},
            headers={"Authorization": f"Bearer {_forge(weak)}"},
        )
        assert r.status_code == 401

    def test_forged_admin_token_cannot_clear_cache(self) -> None:
        client, fake = _build(jwt_secret_key="dev")
        r = client.delete(
            "/api/v1/cache?confirm=true",
            headers={"Authorization": f"Bearer {_forge('dev')}"},
        )
        assert r.status_code in (401, 403)
        assert fake.clear_cache_calls == 0

    def test_forged_token_rejected_on_me(self) -> None:
        client, _ = _build(jwt_secret_key="dev")
        r = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {_forge('dev')}"},
        )
        assert r.status_code in (401, 503)

    def test_weak_secret_rejected_in_debug_too(self) -> None:
        # Debug mode no longer relaxes the strength rules, so a token signed
        # with a short private secret is not trusted there either.
        client, _ = _build(jwt_secret_key="local-dev-only", debug=True)
        r = client.post(
            "/api/v1/enrich",
            json={"ioc": "8.8.8.8"},
            headers={"Authorization": f"Bearer {_forge('local-dev-only')}"},
        )
        assert r.status_code == 401

    def test_generated_secret_works_in_debug(self) -> None:
        client, _ = _build(debug=True, **_ACCOUNT)
        r = client.post(
            "/api/v1/enrich",
            json={"ioc": "8.8.8.8"},
            headers={"Authorization": f"Bearer {_account_token()}"},
        )
        assert r.status_code == 200

    def test_api_key_path_unaffected_by_bad_jwt_config(self) -> None:
        client, _ = _build(
            jwt_secret_key="dev", auth_enabled=True, api_keys=[_API_KEY]
        )
        r = client.post(
            "/api/v1/enrich", json={"ioc": "8.8.8.8"}, headers={"X-API-Key": _API_KEY}
        )
        assert r.status_code == 200


class TestAlgorithmAllowlist:
    @pytest.mark.parametrize("alg", ["none", "RS256", "ES256", "hs256 ", ""])
    def test_unexpected_algorithm_is_config_error(self, alg: str) -> None:
        settings = WebSettings(
            user_auth_enabled=True, jwt_secret_key=_STRONG_SECRET, jwt_algorithm=alg
        )
        with pytest.raises(AuthConfigError):
            resolve_jwt_config(settings)

    def test_unexpected_algorithm_rejected_even_in_debug(self) -> None:
        settings = WebSettings(
            debug=True,
            user_auth_enabled=True,
            jwt_secret_key=_STRONG_SECRET,
            jwt_algorithm="none",
        )
        with pytest.raises(AuthConfigError):
            resolve_jwt_config(settings)

    @pytest.mark.parametrize("alg", sorted(ALLOWED_JWT_ALGORITHMS))
    def test_hmac_algorithms_accepted(self, alg: str) -> None:
        client, _ = _build(jwt_algorithm=alg, **_ACCOUNT)
        r = client.post(
            "/api/v1/enrich",
            json={"ioc": "8.8.8.8"},
            headers={
                "Authorization": f"Bearer {_account_token(algorithm=alg)}"
            },
        )
        assert r.status_code == 200

    def test_token_with_other_hmac_alg_rejected(self) -> None:
        # Server pinned to HS256 must not accept an HS512-signed token.
        client, _ = _build(jwt_algorithm="HS256")
        token = _forge(_STRONG_SECRET, algorithm="HS512")
        r = client.post(
            "/api/v1/enrich",
            json={"ioc": "8.8.8.8"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 401

    def test_alg_none_token_rejected(self) -> None:
        client, _ = _build()
        unsigned = jwt.encode(
            {"sub": "x", "role": "admin", "type": "access", "jti": "j",
             "iss": "ioc-enricher", "iat": 0, "exp": 9999999999},
            key=None,
            algorithm="none",
        )
        r = client.post(
            "/api/v1/enrich",
            json={"ioc": "8.8.8.8"},
            headers={"Authorization": f"Bearer {unsigned}"},
        )
        assert r.status_code == 401

    def test_login_503_for_bad_algorithm(self) -> None:
        client, _ = _build(jwt_algorithm="RS256")
        r = client.post(
            "/api/v1/auth/login", json={"username": "a", "password": "b"}
        )
        assert r.status_code == 503


class TestStartupValidation:
    def test_misconfiguration_logged_at_startup_without_secret(self, caplog) -> None:
        with caplog.at_level(logging.ERROR, logger="ioc_enricher.web.auth"):
            _build(jwt_secret_key="dev-weak-secret-value")
        text = caplog.text
        assert "auth-misconfigured" in text
        assert "dev-weak-secret-value" not in text

    def test_valid_configuration_logs_nothing(self, caplog) -> None:
        with caplog.at_level(logging.ERROR, logger="ioc_enricher.web.auth"):
            _build()
        assert "auth-misconfigured" not in caplog.text

    def test_no_auth_in_production_mode_is_an_error(self, caplog) -> None:
        with caplog.at_level(logging.ERROR, logger="ioc_enricher.web.auth"):
            _build(user_auth_enabled=False, auth_enabled=False, debug=False)
        assert "auth-not-configured" in caplog.text

    def test_no_auth_in_debug_is_logged_too(self, caplog) -> None:
        # The API is closed in debug mode as well, so say why.
        with caplog.at_level(logging.ERROR, logger="ioc_enricher.web.auth"):
            _build(user_auth_enabled=False, auth_enabled=False, debug=True)
        assert "auth-not-configured" in caplog.text

    def test_api_key_auth_counts_as_enabled(self, caplog) -> None:
        with caplog.at_level(logging.WARNING, logger="ioc_enricher.web.auth"):
            _build(user_auth_enabled=False, auth_enabled=True, api_keys=[_API_KEY])
        assert "auth-not-configured" not in caplog.text
        assert "auth-dev-bypass" not in caplog.text

    def test_user_auth_disabled_skips_validation(self, caplog) -> None:
        with caplog.at_level(logging.ERROR, logger="ioc_enricher.web.auth"):
            _build(user_auth_enabled=False, jwt_secret_key=None)
        assert "auth-misconfigured" not in caplog.text
