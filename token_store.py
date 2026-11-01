"""
Refresh-token revocation store (Phase 5a / 5b).

When a user logs out we must make their refresh token unusable even though it
has not yet expired. We do this with a *denylist* keyed by the token's ``jti``.
The same store makes refresh tokens *single-use*: ``/auth/refresh`` calls
:meth:`TokenDenylist.consume`, which atomically marks the presented ``jti`` as
used and reports whether this caller was the first to do so.

Two backends:

* :class:`InMemoryTokenDenylist` — a process-local dict. Works for a single
  worker; revocations are lost on restart and not shared across workers.
* :class:`RedisTokenDenylist` — shared, TTL'd entries. The recommended choice
  for any multi-worker / multi-process deployment.

:func:`build_token_denylist` picks Redis when ``redis_url`` is set *and* the
``redis`` package is importable; otherwise it falls back to in-memory and logs
a single warning.

Failure policy (see SECURITY.md):

* ``consume`` / ``is_revoked`` — **fail closed**. If Redis is unreachable,
  ``consume`` raises :class:`TokenStoreUnavailable` (the refresh endpoint
  answers 503 and issues nothing) and ``is_revoked`` reports ``True``. A
  revoked or already-rotated token must never be honoured just because the
  store blipped. Login itself does not touch the store and keeps working.
* ``revoke`` (logout) — best effort; failures are logged, the cookies are
  still cleared.

Guarantees and limits:

* Redis: ``SET NX EX`` is a single atomic command, so exactly one concurrent
  refresh per token succeeds across *all* workers sharing that Redis.
* In-memory: atomic within one process only. With several workers and no
  Redis, the same refresh token could be rotated once per worker, and
  revocations are lost on restart. Use Redis for multi-worker deployments.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Optional, Protocol

log = logging.getLogger("ioc_enricher.web.auth")


class TokenStoreUnavailable(Exception):
    """The revocation backend could not answer; callers must fail closed."""


class TokenDenylist(Protocol):
    """Interface for refresh-token revocation backends."""

    def revoke(self, jti: str, ttl_seconds: int) -> None:
        """Mark *jti* as revoked for at least *ttl_seconds*."""

    def consume(self, jti: str, ttl_seconds: int) -> bool:
        """
        Atomically mark *jti* as used. Return ``True`` only for the first
        caller; ``False`` if it was already used or revoked. Raises
        :class:`TokenStoreUnavailable` if the backend cannot answer.
        """

    def is_revoked(self, jti: str) -> bool:
        """Return ``True`` iff *jti* was revoked and the entry is still live."""

    def backend_name(self) -> str:
        """Human-readable backend identifier (for diagnostics, no secrets)."""


class InMemoryTokenDenylist:
    """Process-local revocation list. Not shared across workers."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # jti -> unix expiry timestamp
        self._revoked: dict[str, float] = {}

    def revoke(self, jti: str, ttl_seconds: int) -> None:
        if not jti:
            return
        with self._lock:
            self._revoked[jti] = time.time() + max(1, ttl_seconds)
            self._evict_expired_locked()

    def consume(self, jti: str, ttl_seconds: int) -> bool:
        if not jti:
            return False
        with self._lock:
            if self._is_revoked_locked(jti):
                return False
            self._revoked[jti] = time.time() + max(1, ttl_seconds)
            self._evict_expired_locked()
            return True

    def is_revoked(self, jti: str) -> bool:
        if not jti:
            return False
        with self._lock:
            return self._is_revoked_locked(jti)

    def _is_revoked_locked(self, jti: str) -> bool:
        expiry = self._revoked.get(jti)
        if expiry is None:
            return False
        if expiry < time.time():
            self._revoked.pop(jti, None)
            return False
        return True

    def _evict_expired_locked(self) -> None:
        now = time.time()
        stale = [k for k, exp in self._revoked.items() if exp < now]
        for k in stale:
            self._revoked.pop(k, None)

    def backend_name(self) -> str:
        return "in-memory"


class RedisTokenDenylist:
    """Redis-backed revocation list with native key TTLs."""

    _KEY_PREFIX = "ioc:revoked_jti:"

    def __init__(self, client) -> None:
        self._client = client

    def revoke(self, jti: str, ttl_seconds: int) -> None:
        if not jti:
            return
        try:
            self._client.setex(
                self._KEY_PREFIX + jti, max(1, ttl_seconds), "1"
            )
        except Exception:  # noqa: BLE001
            # Logout still clears the cookie; a failed server-side revoke is
            # logged but not fatal.
            log.warning("redis-revoke-failed (jti suppressed)")

    def consume(self, jti: str, ttl_seconds: int) -> bool:
        if not jti:
            return False
        try:
            # SET NX EX is atomic: exactly one caller creates the key.
            created = self._client.set(
                self._KEY_PREFIX + jti, "1", nx=True, ex=max(1, ttl_seconds)
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("redis-consume-failed; failing closed")
            raise TokenStoreUnavailable("revocation store unavailable") from exc
        return bool(created)

    def is_revoked(self, jti: str) -> bool:
        if not jti:
            return False
        try:
            return self._client.exists(self._KEY_PREFIX + jti) == 1
        except Exception:  # noqa: BLE001
            # Fail closed: an unanswerable revocation check must not let a
            # possibly-revoked token through.
            log.warning("redis-revocation-check-failed; failing closed")
            return True

    def backend_name(self) -> str:
        return "redis"


def build_token_denylist(redis_url: Optional[str]) -> TokenDenylist:
    """
    Construct the best available denylist backend.

    Falls back to in-memory (with a warning) when Redis is not configured or
    the ``redis`` package is unavailable.
    """
    if not redis_url:
        return InMemoryTokenDenylist()
    try:
        import redis  # type: ignore

        client = redis.Redis.from_url(
            redis_url, socket_timeout=2, socket_connect_timeout=2
        )
        return RedisTokenDenylist(client)
    except Exception:  # noqa: BLE001
        log.warning(
            "redis package unavailable or misconfigured; "
            "falling back to in-memory token denylist"
        )
        return InMemoryTokenDenylist()
