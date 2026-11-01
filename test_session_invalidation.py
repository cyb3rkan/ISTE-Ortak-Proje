"""
A changed admin password ends the sessions issued before the change.

Every access and refresh token carries a fingerprint of the account's current
credential: an HMAC of the username and the password hash, keyed with the
JWT signing secret. When the bootstrap password hash (or the username)
changes, older tokens stop working at their next use — access tokens at
once, refresh tokens at the next refresh. A restart with the same credential
keeps sessions. Tokens without a fingerprint, as issued before this check
existed, are refused: users sign in once more.

Passwords and the signing secret are generated per run.
"""
from __future__ import annotations

import secrets

import pytest
from fastapi.testclient import TestClient

from ioc_enricher.web.api.app import create_app
from ioc_enricher.web.api.deps import get_enrichment_service
from ioc_enricher.web.api.security.jwt_tokens import (
    ACCESS_TOKEN_TYPE,
    create_access_token,
    create_refresh_token,
    decode_token,
)
from ioc_enricher.web.api.security.password import hash_password
from ioc_enricher.web.settings import WebSettings

from ..conftest import FakeService

_SECRET = secrets.token_hex(32)
_USER = "admin"
_OLD_PASSWORD = "old-" + secrets.token_urlsafe(12)
_NEW_PASSWORD = "new-" + secrets.token_urlsafe(12)


@pytest.fixture(scope="module")
def hashes() -> tuple[str, str]:
    return hash_password(_OLD_PASSWORD), hash_password(_NEW_PASSWORD)


def _client(password_hash: str, *, username: str = _USER, secret: str = _SECRET) -> TestClient:
    settings = WebSettings(
        user_auth_enabled=True,
        jwt_secret_key=secret,
        bootstrap_admin_username=username,
        bootstrap_admin_password_hash=password_hash,
        rate_limit_enabled=False,
    )
    app = create_app(settings)
    app.dependency_overrides[get_enrichment_service] = lambda: FakeService()
    return TestClient(app, raise_server_exceptions=False)


def _session(client: TestClient, password: str) -> tuple[str, str, str]:
    r = client.post("/api/v1/auth/login", json={"username": _USER, "password": password})
    assert r.status_code == 200
    return (r.json()["access_token"], client.cookies.get("ioc_refresh_token"),
            client.cookies.get("ioc_csrf_token"))


def _me(client: TestClient, access: str):
    return client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {access}"})


def _refresh(client: TestClient, refresh: str, csrf: str):
    return client.post("/api/v1/auth/refresh", headers={
        "X-CSRF-Token": csrf, "Cookie": f"ioc_refresh_token={refresh}; ioc_csrf_token={csrf}",
    })


class TestSameCredential:
    def test_a_restart_with_the_same_credential_keeps_the_session(self, hashes) -> None:
        access, refresh, csrf = _session(_client(hashes[0]), _OLD_PASSWORD)
        restarted = _client(hashes[0])
        assert _me(restarted, access).status_code == 200
        assert _refresh(restarted, refresh, csrf).status_code == 200


class TestChangedPassword:
    def test_access_tokens_stop_working_at_once(self, hashes) -> None:
        access, _, _ = _session(_client(hashes[0]), _OLD_PASSWORD)
        assert _me(_client(hashes[1]), access).status_code == 401

    def test_refresh_tokens_cannot_mint_new_sessions(self, hashes) -> None:
        _, refresh, csrf = _session(_client(hashes[0]), _OLD_PASSWORD)
        assert _refresh(_client(hashes[1]), refresh, csrf).status_code == 401

    def test_the_new_password_starts_a_working_session(self, hashes) -> None:
        changed = _client(hashes[1])
        access, refresh, csrf = _session(changed, _NEW_PASSWORD)
        assert _me(changed, access).status_code == 200
        assert _refresh(changed, refresh, csrf).status_code == 200


class TestRenamedAccount:
    def test_sessions_of_the_old_username_end(self, hashes) -> None:
        access, refresh, csrf = _session(_client(hashes[0]), _OLD_PASSWORD)
        renamed = _client(hashes[0], username="soc-admin")
        assert _me(renamed, access).status_code == 401
        assert _refresh(renamed, refresh, csrf).status_code == 401


class TestTokensWithoutFingerprint:
    def test_access_token_without_fingerprint_is_refused(self, hashes) -> None:
        token, _ = create_access_token(subject=_USER, role="admin", secret=_SECRET)
        assert _me(_client(hashes[0]), token).status_code == 401

    def test_refresh_token_without_fingerprint_is_refused(self, hashes) -> None:
        token, _ = create_refresh_token(subject=_USER, role="admin", secret=_SECRET)
        csrf = secrets.token_urlsafe(16)
        assert _refresh(_client(hashes[0]), token, csrf).status_code == 401


class TestFingerprint:
    def test_the_claim_reveals_nothing_about_the_password_hash(self, hashes) -> None:
        access, _, _ = _session(_client(hashes[0]), _OLD_PASSWORD)
        claim = decode_token(access, secret=_SECRET, expected_type=ACCESS_TOKEN_TYPE).credential
        assert claim and len(claim) == 32 and int(claim, 16) >= 0
        assert claim not in hashes[0]

    def test_the_claim_depends_on_the_signing_secret(self, hashes) -> None:
        other_secret = secrets.token_hex(32)
        first, _, _ = _session(_client(hashes[0]), _OLD_PASSWORD)
        second, _, _ = _session(_client(hashes[0], secret=other_secret), _OLD_PASSWORD)
        a = decode_token(first, secret=_SECRET, expected_type=ACCESS_TOKEN_TYPE).credential
        b = decode_token(second, secret=other_secret, expected_type=ACCESS_TOKEN_TYPE).credential
        assert a != b
