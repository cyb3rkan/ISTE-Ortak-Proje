"""
Regression tests for authentication-endpoint rate limiting and trusted-proxy
client identification.

* ``POST /auth/login`` and ``POST /auth/refresh`` are throttled per client so
  repeated guesses cannot burn unbounded Argon2 CPU / brute-force the password.
* ``X-Forwarded-For`` is only honoured when the direct peer is an explicitly
  configured trusted proxy, and is walked right-to-left so client-supplied
  (left-most) entries can never choose the rate-limit identity.
"""
from __future__ import annotations

import logging
import re
import secrets
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

from ioc_enricher.web.api.app import create_app
from ioc_enricher.web.api.deps import get_enrichment_service
from ioc_enricher.web.api.middleware.rate_limit import (
    ClientIdentityResolver,
    RedisRateLimiter,
)
from ioc_enricher.web.api.security.password import hash_password
from ioc_enricher.web.settings import WebSettings, load_settings

from ..conftest import FakeService
from .test_redis_backends import BrokenRedis

_SECRET = secrets.token_hex(32)
_USER = "admin"
_PASS = "AdminStrongPass123"


@pytest.fixture(scope="module")
def admin_hash() -> str:
    return hash_password(_PASS)


def _build(admin_hash: str, **overrides) -> TestClient:
    base = dict(
        user_auth_enabled=True,
        jwt_secret_key=_SECRET,
        bootstrap_admin_username=_USER,
        bootstrap_admin_password_hash=admin_hash,
        rate_limit_enabled=True,
        login_rate_limit_per_minute=3,
        refresh_rate_limit_per_minute=2,
    )
    base.update(overrides)
    app = create_app(WebSettings(**base))
    app.dependency_overrides[get_enrichment_service] = lambda: FakeService()
    return TestClient(app, raise_server_exceptions=False)


def _login(client: TestClient, password: str = _PASS, headers=None):
    return client.post(
        "/api/v1/auth/login",
        json={"username": _USER, "password": password},
        headers=headers or {},
    )


# ---------------------------------------------------------------------------
# Login / refresh throttling
# ---------------------------------------------------------------------------

class TestLoginRateLimit:
    def test_repeated_failed_logins_get_429(self, admin_hash: str) -> None:
        client = _build(admin_hash)
        for _ in range(3):
            assert _login(client, password="wrong").status_code == 401
        r = _login(client, password="wrong")
        assert r.status_code == 429
        assert int(r.headers["Retry-After"]) >= 1
        assert r.headers["content-type"].startswith("application/problem+json")

    def test_correct_password_also_blocked_once_limited(self, admin_hash: str) -> None:
        # Throttling counts attempts, not failures, so a 429 never reveals
        # whether a guess would have been correct.
        client = _build(admin_hash)
        for _ in range(3):
            _login(client, password="wrong")
        assert _login(client).status_code == 429

    def test_legitimate_login_within_limit(self, admin_hash: str) -> None:
        client = _build(admin_hash)
        assert _login(client, password="wrong").status_code == 401
        assert _login(client).status_code == 200

    def test_boundary_exactly_at_limit_allowed(self, admin_hash: str) -> None:
        client = _build(admin_hash, login_rate_limit_per_minute=2)
        assert _login(client, password="wrong").status_code == 401
        assert _login(client).status_code == 200
        assert _login(client).status_code == 429

    def test_429_identical_for_unknown_and_known_user(self, admin_hash: str) -> None:
        client = _build(admin_hash, login_rate_limit_per_minute=1)
        _login(client, password="wrong")
        known = _login(client)
        unknown = client.post(
            "/api/v1/auth/login", json={"username": "nobody", "password": "x"}
        )
        assert known.status_code == unknown.status_code == 429
        assert known.json()["detail"] == unknown.json()["detail"]
        assert _USER not in known.text

    def test_login_bucket_independent_of_enrich(self, admin_hash: str) -> None:
        client = _build(admin_hash, login_rate_limit_per_minute=1)
        _login(client, password="wrong")
        assert _login(client).status_code == 429
        token_free = client.get("/api/v1/health")
        assert token_free.status_code == 200

    def test_trailing_slash_variant_is_counted(self, admin_hash: str) -> None:
        client = _build(admin_hash, login_rate_limit_per_minute=1)
        _login(client, password="wrong")
        r = client.post(
            "/api/v1/auth/login/", json={"username": _USER, "password": _PASS}
        )
        assert r.status_code == 429

    def test_rate_limit_disabled_never_429(self, admin_hash: str) -> None:
        client = _build(admin_hash, rate_limit_enabled=False)
        for _ in range(6):
            assert _login(client, password="wrong").status_code == 401


class TestRefreshRateLimit:
    def test_refresh_throttled(self, admin_hash: str) -> None:
        client = _build(admin_hash)
        assert _login(client).status_code == 200
        statuses = []
        for _ in range(3):
            csrf = client.cookies.get("ioc_csrf_token")
            statuses.append(
                client.post(
                    "/api/v1/auth/refresh", headers={"X-CSRF-Token": csrf}
                ).status_code
            )
        assert statuses[:2] == [200, 200]
        assert statuses[2] == 429


class TestForgedForwardedFor:
    def test_rotating_xff_from_untrusted_peer_cannot_bypass(self, admin_hash: str) -> None:
        # Proxy trust ON, but the TestClient peer is not a trusted proxy:
        # forged X-Forwarded-For values must be ignored.
        client = _build(
            admin_hash,
            trust_proxy_headers=True,
            trusted_proxies=["10.0.0.0/8"],
        )
        codes = [
            _login(
                client, password="wrong",
                headers={"X-Forwarded-For": f"203.0.113.{i}"},
            ).status_code
            for i in range(5)
        ]
        assert codes[:3] == [401, 401, 401]
        assert codes[3:] == [429, 429]

    def test_trust_without_trusted_proxies_ignores_xff(self, admin_hash: str) -> None:
        client = _build(admin_hash, trust_proxy_headers=True)
        codes = [
            _login(
                client, password="wrong",
                headers={"X-Forwarded-For": f"198.51.100.{i}"},
            ).status_code
            for i in range(4)
        ]
        assert codes[-1] == 429


# ---------------------------------------------------------------------------
# ClientIdentityResolver unit tests
# ---------------------------------------------------------------------------

def _request(peer: str | None, *xff: str) -> Request:
    headers = [(b"x-forwarded-for", v.encode()) for v in xff]
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": headers,
        "client": (peer, 1234) if peer is not None else None,
    }
    return Request(scope)


class TestClientIdentityResolver:
    def test_trust_disabled_uses_peer(self) -> None:
        r = ClientIdentityResolver(trust_proxy=False, trusted_proxies=["10.0.0.0/8"])
        assert r.resolve(_request("10.0.0.2", "1.2.3.4")) == "10.0.0.2"

    def test_no_trusted_proxies_uses_peer(self) -> None:
        r = ClientIdentityResolver(trust_proxy=True, trusted_proxies=[])
        assert r.resolve(_request("10.0.0.2", "1.2.3.4")) == "10.0.0.2"

    def test_untrusted_peer_xff_ignored(self) -> None:
        r = ClientIdentityResolver(trust_proxy=True, trusted_proxies=["10.0.0.0/8"])
        assert r.resolve(_request("192.0.2.9", "1.2.3.4")) == "192.0.2.9"

    def test_single_trusted_proxy(self) -> None:
        r = ClientIdentityResolver(trust_proxy=True, trusted_proxies=["10.0.0.2"])
        assert r.resolve(_request("10.0.0.2", "1.2.3.4")) == "1.2.3.4"

    def test_client_supplied_left_entries_ignored(self) -> None:
        # nginx $proxy_add_x_forwarded_for appends the real peer on the right;
        # everything to its left is attacker-controlled.
        r = ClientIdentityResolver(trust_proxy=True, trusted_proxies=["10.0.0.2"])
        req = _request("10.0.0.2", "6.6.6.6, 7.7.7.7, 1.2.3.4")
        assert r.resolve(req) == "1.2.3.4"

    def test_multiple_trusted_hops(self) -> None:
        r = ClientIdentityResolver(trust_proxy=True, trusted_proxies=["10.0.0.0/8"])
        req = _request("10.0.0.2", "6.6.6.6, 1.2.3.4, 10.0.0.7")
        assert r.resolve(req) == "1.2.3.4"

    def test_multiple_header_lines_combined(self) -> None:
        r = ClientIdentityResolver(trust_proxy=True, trusted_proxies=["10.0.0.0/8"])
        req = _request("10.0.0.2", "6.6.6.6", "1.2.3.4, 10.0.0.7")
        assert r.resolve(req) == "1.2.3.4"

    def test_all_hops_trusted_returns_leftmost_trusted(self) -> None:
        r = ClientIdentityResolver(trust_proxy=True, trusted_proxies=["10.0.0.0/8"])
        assert r.resolve(_request("10.0.0.2", "10.0.0.9")) == "10.0.0.9"

    @pytest.mark.parametrize("bad", ["garbage", "1.2.3.4.5", "", "unknown", "1.2.3.4;drop"])
    def test_malformed_hop_stops_walk(self, bad: str) -> None:
        r = ClientIdentityResolver(trust_proxy=True, trusted_proxies=["10.0.0.0/8"])
        req = _request("10.0.0.2", f"1.2.3.4, {bad}")
        # Cannot trust anything beyond a malformed hop: fall back to the last
        # trusted address we actually saw.
        assert r.resolve(req) == "10.0.0.2"

    def test_missing_xff_uses_peer(self) -> None:
        r = ClientIdentityResolver(trust_proxy=True, trusted_proxies=["10.0.0.0/8"])
        assert r.resolve(_request("10.0.0.2")) == "10.0.0.2"

    def test_ipv6_chain(self) -> None:
        r = ClientIdentityResolver(trust_proxy=True, trusted_proxies=["fd00::/8"])
        req = _request("fd00::1", "2001:db8::bad, 2001:db8::5")
        assert r.resolve(req) == "2001:db8::5"

    def test_ipv6_normalised(self) -> None:
        r = ClientIdentityResolver(trust_proxy=True, trusted_proxies=["fd00::/8"])
        req = _request("fd00::1", "2001:DB8:0:0::5")
        assert r.resolve(req) == "2001:db8::5"

    def test_ipv4_mapped_ipv6_peer_matches_ipv4_network(self) -> None:
        r = ClientIdentityResolver(trust_proxy=True, trusted_proxies=["10.0.0.0/8"])
        assert r.resolve(_request("::ffff:10.0.0.2", "1.2.3.4")) == "1.2.3.4"

    def test_bracketed_ipv6_and_port_forms(self) -> None:
        r = ClientIdentityResolver(trust_proxy=True, trusted_proxies=["10.0.0.0/8"])
        assert r.resolve(_request("10.0.0.2", "[2001:db8::5]:443")) == "2001:db8::5"
        assert r.resolve(_request("10.0.0.2", "1.2.3.4:5555")) == "1.2.3.4"

    def test_no_peer(self) -> None:
        r = ClientIdentityResolver(trust_proxy=True, trusted_proxies=["10.0.0.0/8"])
        assert r.resolve(_request(None, "1.2.3.4")) == "unknown"

    def test_invalid_trusted_proxy_entries_ignored(self, caplog) -> None:
        with caplog.at_level(logging.WARNING):
            r = ClientIdentityResolver(
                trust_proxy=True, trusted_proxies=["not-a-cidr", "10.0.0.2"]
            )
        assert "not-a-cidr" in caplog.text
        assert r.resolve(_request("10.0.0.2", "1.2.3.4")) == "1.2.3.4"


# ---------------------------------------------------------------------------
# Redis outage: degrade to per-process limiting, never to "no limit"
# ---------------------------------------------------------------------------

class TestRedisOutageFallback:
    def test_broken_redis_still_enforces_limit(self) -> None:
        limiter = RedisRateLimiter(BrokenRedis())
        limiter.configure("auth_login", 2)
        assert limiter.check("auth_login", "ip1") is None
        assert limiter.check("auth_login", "ip1") is None
        retry = limiter.check("auth_login", "ip1")
        assert retry is not None and retry > 0


# ---------------------------------------------------------------------------
# Settings plumbing
# ---------------------------------------------------------------------------

class TestSettingsFromEnv:
    def test_env_parsing(self, monkeypatch) -> None:
        monkeypatch.setenv("IOC_WEB_LOGIN_RATE_LIMIT_PER_MIN", "7")
        monkeypatch.setenv("IOC_WEB_REFRESH_RATE_LIMIT_PER_MIN", "11")
        monkeypatch.setenv("IOC_WEB_TRUSTED_PROXIES", "10.0.0.0/8, 172.16.0.1 ,")
        s = load_settings()
        assert s.login_rate_limit_per_minute == 7
        assert s.refresh_rate_limit_per_minute == 11
        assert s.trusted_proxies == ["10.0.0.0/8", "172.16.0.1"]

    def test_defaults(self, monkeypatch) -> None:
        for name in (
            "IOC_WEB_LOGIN_RATE_LIMIT_PER_MIN",
            "IOC_WEB_REFRESH_RATE_LIMIT_PER_MIN",
            "IOC_WEB_TRUSTED_PROXIES",
        ):
            monkeypatch.delenv(name, raising=False)
        s = load_settings()
        assert s.login_rate_limit_per_minute == 10
        assert s.refresh_rate_limit_per_minute == 30
        assert s.trusted_proxies == []


# ---------------------------------------------------------------------------
# docker/docker-compose.yml profile
# ---------------------------------------------------------------------------

_COMPOSE = Path(__file__).resolve().parents[2] / "docker" / "docker-compose.yml"


class TestDockerComposeProxyProfile:
    def _nginx_ip_defaults(self) -> set[str]:
        text = _COMPOSE.read_text(encoding="utf-8")
        return set(re.findall(r"\$\{IOC_NGINX_IP:-([^}]+)\}", text))

    def test_nginx_ip_default_is_consistent(self) -> None:
        # The trusted-proxy allowlist and nginx's fixed address must not drift.
        defaults = self._nginx_ip_defaults()
        assert len(defaults) == 1, defaults

    def test_trusts_only_the_nginx_address(self) -> None:
        text = _COMPOSE.read_text(encoding="utf-8")
        assert 'IOC_WEB_TRUST_PROXY_HEADERS: "true"' in text
        assert re.search(r'IOC_WEB_TRUSTED_PROXIES: "\$\{IOC_NGINX_IP:-[^}]+\}"', text)

    def test_resolver_with_compose_values(self) -> None:
        (nginx_ip,) = self._nginx_ip_defaults()
        r = ClientIdentityResolver(trust_proxy=True, trusted_proxies=[nginx_ip])
        # nginx appends the real peer on the right; spoofed left part ignored.
        assert r.resolve(_request(nginx_ip, "6.6.6.6, 203.0.113.7")) == "203.0.113.7"
        # Another container on ioc-net (e.g. redis) cannot spoof.
        assert r.resolve(_request("172.28.0.3", "203.0.113.99")) == "172.28.0.3"
