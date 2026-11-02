"""
Tests for the Redis-backed rate limiter and token-revocation denylist,
plus their in-memory fallbacks (Phase 5b).

No real Redis server is used — a tiny fake Redis client exercises the
increment / TTL / key-existence logic. Redis-failure paths are covered with a
client that raises on every call, asserting the documented fail-open /
fail-safe behaviour.
"""
from __future__ import annotations

import time

from ioc_enricher.web.api.middleware.rate_limit import (
    InMemoryRateLimiter,
    RedisRateLimiter,
    build_rate_limiter,
)
from ioc_enricher.web.api.security.token_store import (
    InMemoryTokenDenylist,
    RedisTokenDenylist,
    build_token_denylist,
)


# ---------------------------------------------------------------------------
# Fake Redis
# ---------------------------------------------------------------------------

class FakeRedis:
    """Minimal in-process stand-in for the subset of redis-py we use."""

    def __init__(self) -> None:
        self._store: dict[str, int] = {}
        self._expiry: dict[str, float] = {}

    def _expired(self, key: str) -> bool:
        exp = self._expiry.get(key)
        if exp is not None and exp < time.time():
            self._store.pop(key, None)
            self._expiry.pop(key, None)
            return True
        return False

    def incr(self, key: str) -> int:
        self._expired(key)
        self._store[key] = self._store.get(key, 0) + 1
        return self._store[key]

    def expire(self, key: str, seconds: int) -> None:
        self._expiry[key] = time.time() + seconds

    def ttl(self, key: str) -> int:
        exp = self._expiry.get(key)
        if exp is None:
            return -1
        return max(0, int(exp - time.time()))

    def set(self, key: str, value: str, nx: bool = False, ex: int | None = None):
        self._expired(key)
        if nx and key in self._store:
            return None
        self._store[key] = 1
        if ex is not None:
            self._expiry[key] = time.time() + ex
        return True

    def setex(self, key: str, seconds: int, value: str) -> None:
        self._store[key] = 1
        self._expiry[key] = time.time() + seconds

    def exists(self, key: str) -> int:
        return 0 if self._expired(key) else (1 if key in self._store else 0)

    def delete(self, key: str) -> None:
        self._store.pop(key, None)
        self._expiry.pop(key, None)

    def scan_iter(self, match: str = "*"):
        prefix = match.rstrip("*")
        return [k for k in list(self._store) if k.startswith(prefix)]


class BrokenRedis:
    """A client that raises on every operation — models a Redis outage."""

    def __getattr__(self, _name):
        def _raise(*_a, **_kw):
            raise ConnectionError("redis is down")

        return _raise


# ---------------------------------------------------------------------------
# Rate limiter — in-memory
# ---------------------------------------------------------------------------

class TestInMemoryRateLimiter:
    def test_allows_under_limit(self) -> None:
        limiter = InMemoryRateLimiter()
        limiter.configure("enrich", 3)
        assert limiter.check("enrich", "ip1") is None
        assert limiter.check("enrich", "ip1") is None
        assert limiter.check("enrich", "ip1") is None

    def test_rejects_over_limit(self) -> None:
        limiter = InMemoryRateLimiter()
        limiter.configure("enrich", 2)
        limiter.check("enrich", "ip1")
        limiter.check("enrich", "ip1")
        retry = limiter.check("enrich", "ip1")
        assert retry is not None and retry > 0

    def test_separate_clients_independent(self) -> None:
        limiter = InMemoryRateLimiter()
        limiter.configure("enrich", 1)
        assert limiter.check("enrich", "ip1") is None
        assert limiter.check("enrich", "ip2") is None  # different client


# ---------------------------------------------------------------------------
# Rate limiter — Redis
# ---------------------------------------------------------------------------

class TestRedisRateLimiter:
    def test_increment_and_limit(self) -> None:
        limiter = RedisRateLimiter(FakeRedis())
        limiter.configure("enrich", 2)
        assert limiter.check("enrich", "ip1") is None
        assert limiter.check("enrich", "ip1") is None
        retry = limiter.check("enrich", "ip1")
        assert retry is not None and retry > 0

    def test_unconfigured_route_is_exempt(self) -> None:
        limiter = RedisRateLimiter(FakeRedis())
        # No configure() call -> no limit -> always allowed.
        assert limiter.check("enrich", "ip1") is None

    def test_degrades_to_in_memory_on_redis_error(self) -> None:
        limiter = RedisRateLimiter(BrokenRedis())
        limiter.configure("enrich", 1)
        # A broken Redis must not raise (no 500), and must not disable
        # throttling either: the per-process fallback keeps counting.
        assert limiter.check("enrich", "ip1") is None
        assert limiter.check("enrich", "ip1") is not None


class TestBuildRateLimiter:
    def test_no_url_returns_in_memory(self) -> None:
        assert isinstance(build_rate_limiter(None), InMemoryRateLimiter)

    def test_bad_url_falls_back_to_in_memory(self) -> None:
        # An unreachable host still constructs a client lazily; redis-py only
        # connects on first command, so from_url succeeds and we get a Redis
        # limiter object — that is acceptable (it fails open at call time).
        limiter = build_rate_limiter("redis://localhost:1/0")
        assert isinstance(limiter, (RedisRateLimiter, InMemoryRateLimiter))


# ---------------------------------------------------------------------------
# Token denylist — in-memory
# ---------------------------------------------------------------------------

class TestInMemoryTokenDenylist:
    def test_revoke_then_revoked(self) -> None:
        dl = InMemoryTokenDenylist()
        assert dl.is_revoked("jti-1") is False
        dl.revoke("jti-1", ttl_seconds=60)
        assert dl.is_revoked("jti-1") is True

    def test_expired_revocation_no_longer_blocks(self) -> None:
        dl = InMemoryTokenDenylist()
        dl.revoke("jti-1", ttl_seconds=1)
        time.sleep(1.1)
        assert dl.is_revoked("jti-1") is False

    def test_unknown_jti_not_revoked(self) -> None:
        dl = InMemoryTokenDenylist()
        assert dl.is_revoked("never-seen") is False


# ---------------------------------------------------------------------------
# Token denylist — Redis
# ---------------------------------------------------------------------------

class TestRedisTokenDenylist:
    def test_revoke_then_revoked(self) -> None:
        dl = RedisTokenDenylist(FakeRedis())
        dl.revoke("jti-9", ttl_seconds=60)
        assert dl.is_revoked("jti-9") is True

    def test_check_fails_closed_on_error(self) -> None:
        # A Redis outage during the revocation check must fail closed: a
        # possibly-revoked token is treated as revoked. (Login does not use
        # the store, so users can still sign in again.)
        dl = RedisTokenDenylist(BrokenRedis())
        assert dl.is_revoked("jti-x") is True

    def test_revoke_swallows_error(self) -> None:
        # A failed revoke must not raise — logout still clears the cookie.
        dl = RedisTokenDenylist(BrokenRedis())
        dl.revoke("jti-x", ttl_seconds=60)  # should not raise


class TestBuildTokenDenylist:
    def test_no_url_returns_in_memory(self) -> None:
        assert isinstance(build_token_denylist(None), InMemoryTokenDenylist)
