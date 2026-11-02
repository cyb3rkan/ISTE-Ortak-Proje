"""
Regression tests: refresh tokens are single-use.

Before the fix, ``POST /auth/refresh`` minted a new refresh token but never
invalidated the presented one, so a stolen refresh cookie stayed usable for
its whole lifetime (7 days by default) even after the legitimate user had
rotated it.
"""
from __future__ import annotations

import secrets
import threading
import time
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi.testclient import TestClient

from ioc_enricher.web.api.app import create_app
from ioc_enricher.web.api.deps import get_enrichment_service
from ioc_enricher.web.api.security.password import hash_password
from ioc_enricher.web.api.security.token_store import (
    InMemoryTokenDenylist,
    RedisTokenDenylist,
    TokenStoreUnavailable,
)
from ioc_enricher.web.settings import WebSettings

from ..conftest import FakeService
from .test_redis_backends import BrokenRedis, FakeRedis

_SECRET = secrets.token_hex(32)
_USER = "admin"
_PASS = "AdminStrongPass123"
_REFRESH = "ioc_refresh_token"
_CSRF = "ioc_csrf_token"


@pytest.fixture(scope="module")
def admin_hash() -> str:
    return hash_password(_PASS)


def _build(admin_hash: str) -> TestClient:
    settings = WebSettings(
        user_auth_enabled=True,
        jwt_secret_key=_SECRET,
        bootstrap_admin_username=_USER,
        bootstrap_admin_password_hash=admin_hash,
        rate_limit_enabled=False,
    )
    app = create_app(settings)
    app.dependency_overrides[get_enrichment_service] = lambda: FakeService()
    return TestClient(app, raise_server_exceptions=False)


def _login(client: TestClient) -> None:
    r = client.post("/api/v1/auth/login", json={"username": _USER, "password": _PASS})
    assert r.status_code == 200


def _refresh_with(client: TestClient, refresh: str, csrf: str):
    client.cookies.set(_REFRESH, refresh)
    client.cookies.set(_CSRF, csrf)
    return client.post("/api/v1/auth/refresh", headers={"X-CSRF-Token": csrf})


# ---------------------------------------------------------------------------
# HTTP-level behaviour
# ---------------------------------------------------------------------------

class TestSingleUseRefresh:
    def test_old_refresh_token_cannot_be_replayed(self, admin_hash: str) -> None:
        client = _build(admin_hash)
        _login(client)
        old_refresh = client.cookies.get(_REFRESH)
        csrf = client.cookies.get(_CSRF)

        first = _refresh_with(client, old_refresh, csrf)
        assert first.status_code == 200

        replay = _refresh_with(client, old_refresh, csrf)
        assert replay.status_code == 401
        assert "access_token" not in replay.text

    def test_rotation_chain_keeps_working(self, admin_hash: str) -> None:
        client = _build(admin_hash)
        _login(client)
        seen = {client.cookies.get(_REFRESH)}
        for _ in range(3):
            csrf = client.cookies.get(_CSRF)
            r = client.post("/api/v1/auth/refresh", headers={"X-CSRF-Token": csrf})
            assert r.status_code == 200
            new = client.cookies.get(_REFRESH)
            assert new not in seen
            seen.add(new)

    def test_new_access_token_works_after_rotation(self, admin_hash: str) -> None:
        client = _build(admin_hash)
        _login(client)
        csrf = client.cookies.get(_CSRF)
        token = client.post(
            "/api/v1/auth/refresh", headers={"X-CSRF-Token": csrf}
        ).json()["access_token"]
        me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert me.status_code == 200

    def test_concurrent_refresh_with_same_token_only_one_wins(self, admin_hash: str) -> None:
        client = _build(admin_hash)
        _login(client)
        refresh = client.cookies.get(_REFRESH)
        csrf = client.cookies.get(_CSRF)
        results: list[int] = []
        lock = threading.Lock()
        barrier = threading.Barrier(5)

        def worker() -> None:
            c = TestClient(client.app, raise_server_exceptions=False)
            c.cookies.set(_REFRESH, refresh)
            c.cookies.set(_CSRF, csrf)
            barrier.wait()
            code = c.post(
                "/api/v1/auth/refresh", headers={"X-CSRF-Token": csrf}
            ).status_code
            with lock:
                results.append(code)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert sorted(results) == [200, 401, 401, 401, 401]

    def test_expired_refresh_token_rejected(self, admin_hash: str) -> None:
        client = _build(admin_hash)
        _login(client)
        csrf = client.cookies.get(_CSRF)
        past = datetime.now(timezone.utc) - timedelta(days=1)
        # Every claim except ``exp`` is valid, so expiry is what rejects it.
        expired = jwt.encode(
            {"sub": _USER, "role": "admin", "type": "refresh", "jti": "x" * 32,
             "iss": "ioc-enricher", "aud": "ioc-enricher-auth-refresh",
             "iat": past - timedelta(days=7),
             "nbf": past - timedelta(days=7), "exp": past},
            _SECRET, algorithm="HS256",
        )
        assert _refresh_with(client, expired, csrf).status_code == 401

    def test_logout_after_rotation_revokes_current_token(self, admin_hash: str) -> None:
        client = _build(admin_hash)
        _login(client)
        csrf = client.cookies.get(_CSRF)
        assert client.post(
            "/api/v1/auth/refresh", headers={"X-CSRF-Token": csrf}
        ).status_code == 200
        current = client.cookies.get(_REFRESH)
        csrf = client.cookies.get(_CSRF)
        assert client.post(
            "/api/v1/auth/logout", headers={"X-CSRF-Token": csrf}
        ).status_code == 200
        assert _refresh_with(client, current, csrf).status_code == 401


class TestRefreshUsesCurrentAccountState:
    """Role / account changes must take effect at the next refresh."""

    def _rebuild_sharing_store(self, client: TestClient, admin_hash: str, **overrides):
        settings = WebSettings(
            user_auth_enabled=True,
            jwt_secret_key=_SECRET,
            bootstrap_admin_username=overrides.get("username", _USER),
            bootstrap_admin_password_hash=admin_hash,
            bootstrap_admin_role=overrides.get("role", "admin"),
            rate_limit_enabled=False,
        )
        app = create_app(settings)
        app.state.token_denylist = client.app.state.token_denylist
        new = TestClient(app, raise_server_exceptions=False)
        new.cookies.set(_REFRESH, client.cookies.get(_REFRESH))
        new.cookies.set(_CSRF, client.cookies.get(_CSRF))
        return new

    def test_role_downgrade_applies_on_refresh(self, admin_hash: str) -> None:
        client = _build(admin_hash)
        _login(client)
        demoted = self._rebuild_sharing_store(client, admin_hash, role="analyst")
        csrf = demoted.cookies.get(_CSRF)
        r = demoted.post("/api/v1/auth/refresh", headers={"X-CSRF-Token": csrf})
        assert r.status_code == 200
        assert r.json()["user"]["role"] == "analyst"

    def test_removed_user_cannot_refresh(self, admin_hash: str) -> None:
        client = _build(admin_hash)
        _login(client)
        renamed = self._rebuild_sharing_store(client, admin_hash, username="someone-else")
        csrf = renamed.cookies.get(_CSRF)
        r = renamed.post("/api/v1/auth/refresh", headers={"X-CSRF-Token": csrf})
        assert r.status_code == 401


class TestRevocationBackendFailure:
    def _client_with_store(self, admin_hash: str, store) -> TestClient:
        client = _build(admin_hash)
        client.app.state.token_denylist = store
        return client

    def test_refresh_fails_closed_when_store_down(self, admin_hash: str) -> None:
        client = self._client_with_store(admin_hash, RedisTokenDenylist(BrokenRedis()))
        _login(client)
        csrf = client.cookies.get(_CSRF)
        r = client.post("/api/v1/auth/refresh", headers={"X-CSRF-Token": csrf})
        assert r.status_code == 503
        assert "access_token" not in r.text
        assert _REFRESH + "=" not in " ".join(r.headers.get_list("set-cookie"))

    def test_logout_still_clears_cookies_when_store_down(self, admin_hash: str) -> None:
        client = self._client_with_store(admin_hash, RedisTokenDenylist(BrokenRedis()))
        _login(client)
        csrf = client.cookies.get(_CSRF)
        r = client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": csrf})
        assert r.status_code == 200

    def test_redis_store_rotation(self, admin_hash: str) -> None:
        client = self._client_with_store(admin_hash, RedisTokenDenylist(FakeRedis()))
        _login(client)
        old = client.cookies.get(_REFRESH)
        csrf = client.cookies.get(_CSRF)
        assert _refresh_with(client, old, csrf).status_code == 200
        assert _refresh_with(client, old, csrf).status_code == 401


# ---------------------------------------------------------------------------
# Store-level semantics
# ---------------------------------------------------------------------------

class TestConsumeSemantics:
    @pytest.mark.parametrize(
        "factory", [InMemoryTokenDenylist, lambda: RedisTokenDenylist(FakeRedis())]
    )
    def test_consume_once(self, factory) -> None:
        store = factory()
        assert store.consume("jti-1", 60) is True
        assert store.consume("jti-1", 60) is False
        assert store.is_revoked("jti-1") is True

    @pytest.mark.parametrize(
        "factory", [InMemoryTokenDenylist, lambda: RedisTokenDenylist(FakeRedis())]
    )
    def test_revoked_cannot_be_consumed(self, factory) -> None:
        store = factory()
        store.revoke("jti-2", 60)
        assert store.consume("jti-2", 60) is False

    def test_empty_jti_never_consumable(self) -> None:
        assert InMemoryTokenDenylist().consume("", 60) is False
        assert RedisTokenDenylist(FakeRedis()).consume("", 60) is False

    def test_in_memory_consume_is_atomic_under_threads(self) -> None:
        store = InMemoryTokenDenylist()
        wins: list[bool] = []
        barrier = threading.Barrier(16)

        def worker() -> None:
            barrier.wait()
            wins.append(store.consume("race", 60))

        threads = [threading.Thread(target=worker) for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert wins.count(True) == 1

    def test_consumed_entry_expires(self) -> None:
        store = InMemoryTokenDenylist()
        assert store.consume("short", 1) is True
        time.sleep(1.1)
        # After the token's own expiry the entry may be forgotten; the JWT
        # itself is expired by then, so decode rejects it independently.
        assert store.is_revoked("short") is False

    def test_redis_consume_raises_when_down(self) -> None:
        with pytest.raises(TokenStoreUnavailable):
            RedisTokenDenylist(BrokenRedis()).consume("jti", 60)

    def test_redis_is_revoked_fails_closed(self) -> None:
        assert RedisTokenDenylist(BrokenRedis()).is_revoked("jti") is True
