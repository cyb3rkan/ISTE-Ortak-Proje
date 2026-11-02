"""
Per-IP, per-route fixed-window rate limiting.

Two backends share one ``check(route_key, client_id) -> Optional[int]``
contract:

* :class:`InMemoryRateLimiter` — per-process state. Fine for a single worker;
  **not** coordinated across workers.
* :class:`RedisRateLimiter` — shared fixed-window counters with native TTL.
  The recommended choice for any multi-worker production deployment.

:func:`build_rate_limiter` picks Redis when a URL is supplied and the
``redis`` package imports; otherwise it falls back to in-memory with a
warning. If Redis is configured but a *runtime* call fails, the Redis backend
fails **open** (logs a warning, allows the request) — a transient cache
outage must not take down the public API. Instead of failing fully open, the
Redis backend degrades to a per-process in-memory limiter for the duration of
the outage, so brute-force protection on the auth routes keeps working (with
per-worker rather than global counters). See SECURITY.md.

Design notes:

* Each ``(route_key, client_ip)`` pair gets its own 60-second window.
* Limits are configured per-route via ``configure``.
* Health/docs/static routes are unrestricted (the API layer never registers
  a limit for them).
* Client identity comes from :class:`ClientIdentityResolver`: the direct peer
  address, unless proxy-header trust is on *and* the peer is an explicitly
  configured trusted proxy. In that case ``X-Forwarded-For`` is walked
  right-to-left, skipping trusted hops, and the first untrusted address is
  the client. Left-most (client-supplied) entries are never trusted blindly.
"""
from __future__ import annotations

import ipaddress
import logging
import threading
import time
from collections import defaultdict
from typing import Dict, Iterable, List, Optional, Tuple, Union

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse


_WINDOW_SECONDS = 60.0
_PROBLEM_MEDIA_TYPE = "application/problem+json"

log = logging.getLogger("ioc_enricher.web.ratelimit")


class InMemoryRateLimiter:
    """Tiny fixed-window per-(route, client) limiter."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._limits: Dict[str, int] = {}
        self._state: Dict[Tuple[str, str], Tuple[float, int]] = defaultdict(
            lambda: (0.0, 0)
        )

    def configure(self, route_key: str, per_minute: int) -> None:
        with self._lock:
            self._limits[route_key] = max(0, int(per_minute))

    def reset(self) -> None:
        with self._lock:
            self._state.clear()

    def check(self, route_key: str, client_id: str) -> Optional[int]:
        """
        Return ``None`` if the request is allowed, or the number of seconds
        until the current window resets if it is rejected.
        """
        with self._lock:
            limit = self._limits.get(route_key)
            if limit is None or limit <= 0:
                return None

            now = time.monotonic()
            window_start, count = self._state[(route_key, client_id)]

            if now - window_start >= _WINDOW_SECONDS:
                # New window.
                self._state[(route_key, client_id)] = (now, 1)
                return None

            if count >= limit:
                retry_after = max(1, int(_WINDOW_SECONDS - (now - window_start)))
                return retry_after

            self._state[(route_key, client_id)] = (window_start, count + 1)
            return None


class RedisRateLimiter:
    """
    Redis-backed fixed-window limiter.

    For each ``(route_key, client_id)`` we ``INCR`` a per-minute-bucket key
    and set its TTL on first use. The bucket id is ``floor(now / 60)`` so the
    window rolls without a background sweep.

    On any Redis error ``check`` logs a warning and falls back to an
    in-process limiter, so an outage neither 500s the API nor removes
    throttling altogether.
    """

    _KEY_PREFIX = "ioc:ratelimit:"

    def __init__(self, client) -> None:
        self._client = client
        self._lock = threading.Lock()
        self._limits: Dict[str, int] = {}
        # Used only while Redis is unreachable: per-process counters are a
        # weaker guarantee than global ones, but far better than no limit.
        self._fallback = InMemoryRateLimiter()

    def configure(self, route_key: str, per_minute: int) -> None:
        with self._lock:
            self._limits[route_key] = max(0, int(per_minute))
        self._fallback.configure(route_key, per_minute)

    def reset(self) -> None:
        self._fallback.reset()
        # Best-effort: only used by tests. Scans this limiter's namespace.
        try:
            for key in self._client.scan_iter(match=f"{self._KEY_PREFIX}*"):
                self._client.delete(key)
        except Exception:  # noqa: BLE001
            log.warning("redis-ratelimit-reset-failed")

    def check(self, route_key: str, client_id: str) -> Optional[int]:
        limit = self._limits.get(route_key)
        if limit is None or limit <= 0:
            return None

        bucket = int(time.time() // _WINDOW_SECONDS)
        key = f"{self._KEY_PREFIX}{route_key}:{client_id}:{bucket}"
        try:
            count = self._client.incr(key)
            if count == 1:
                # First hit in this window — expire the key when the window
                # closes (plus a small grace margin).
                self._client.expire(key, int(_WINDOW_SECONDS) + 1)
            if count > limit:
                ttl = self._client.ttl(key)
                return max(1, int(ttl)) if ttl and ttl > 0 else int(
                    _WINDOW_SECONDS
                )
            return None
        except Exception:  # noqa: BLE001
            # A Redis blip must not 500 the public API — but must not disable
            # throttling either. Degrade to per-process counters.
            log.warning("redis-ratelimit-check-failed; using in-memory fallback")
            return self._fallback.check(route_key, client_id)


def build_rate_limiter(redis_url: Optional[str]):
    """
    Construct the best available rate limiter.

    Returns a :class:`RedisRateLimiter` when *redis_url* is set and the
    ``redis`` package is importable; otherwise an :class:`InMemoryRateLimiter`
    (with a warning, since that backend is not multi-worker safe).
    """
    if not redis_url:
        return InMemoryRateLimiter()
    try:
        import redis  # type: ignore

        client = redis.Redis.from_url(
            redis_url, socket_timeout=2, socket_connect_timeout=2
        )
        log.info("rate limiting: using Redis backend")
        return RedisRateLimiter(client)
    except Exception:  # noqa: BLE001
        log.warning(
            "redis package unavailable or misconfigured; "
            "falling back to in-memory rate limiting (not multi-worker safe)"
        )
        return InMemoryRateLimiter()


def _classify(path: str, method: str, api_prefix: str) -> Optional[str]:
    """Map a (method, path) to a configured route key, or None if exempt."""
    prefix = api_prefix.rstrip("/")
    if not path.startswith(prefix):
        return None

    rest = path[len(prefix):] or "/"
    if rest in {"/health", "/health/"}:
        return None  # health is never throttled

    method_u = method.upper()
    if rest in {"/enrich", "/enrich/"} and method_u == "POST":
        return "enrich"
    if rest in {"/enrich/batch", "/enrich/batch/"} and method_u == "POST":
        return "enrich_batch"
    if rest in {"/cache", "/cache/"} and method_u == "DELETE":
        return "clear_cache"
    if rest in {"/auth/login", "/auth/login/"} and method_u == "POST":
        return "auth_login"
    if rest in {"/auth/refresh", "/auth/refresh/"} and method_u == "POST":
        return "auth_refresh"
    return None


_IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
_IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


def _parse_ip(value: str) -> Optional[_IPAddress]:
    """
    Parse one forwarded-for hop. Accepts bare IPv4/IPv6, ``[v6]:port`` and
    ``v4:port``. IPv4-mapped IPv6 is normalised to IPv4. Returns ``None`` for
    anything else (``unknown``, obfuscated identifiers, garbage).
    """
    v = value.strip()
    if not v:
        return None
    if v.startswith("["):
        end = v.find("]")
        if end == -1:
            return None
        v = v[1:end]
    elif v.count(":") == 1:
        v = v.split(":", 1)[0]  # IPv4 with port
    try:
        ip = ipaddress.ip_address(v)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


class ClientIdentityResolver:
    """
    Derive the rate-limit identity of a request.

    * Proxy trust off, or no trusted proxies configured -> direct peer.
    * Peer is not a trusted proxy (e.g. someone reaching the app port
      directly) -> direct peer; its forwarding headers are ignored.
    * Otherwise walk ``X-Forwarded-For`` from the right. Each trusted hop is
      skipped; the first untrusted address is the client. A malformed hop
      stops the walk and the last trusted address seen is used, because
      nothing to its left can be attributed reliably.
    """

    def __init__(self, *, trust_proxy: bool, trusted_proxies: Iterable[str] = ()) -> None:
        networks: List[_IPNetwork] = []
        for entry in trusted_proxies:
            try:
                networks.append(ipaddress.ip_network(entry.strip(), strict=False))
            except ValueError:
                log.warning("ignoring invalid trusted proxy entry: %r", entry)
        self._networks = tuple(networks)
        self._trust_proxy = bool(trust_proxy)
        if self._trust_proxy and not self._networks:
            log.warning(
                "IOC_WEB_TRUST_PROXY_HEADERS is on but IOC_WEB_TRUSTED_PROXIES is "
                "empty; X-Forwarded-For will be ignored"
            )

    def _is_trusted(self, ip: _IPAddress) -> bool:
        return any(ip.version == n.version and ip in n for n in self._networks)

    def resolve(self, request: Request) -> str:
        client = request.client
        peer_raw = client.host if client and client.host else None
        if peer_raw is None:
            return "unknown"
        peer = _parse_ip(peer_raw)
        if peer is None:
            return peer_raw
        if not self._trust_proxy or not self._networks or not self._is_trusted(peer):
            return str(peer)

        hops: List[str] = []
        for line in request.headers.getlist("x-forwarded-for"):
            hops.extend(line.split(","))

        current = peer
        for hop in reversed(hops):
            ip = _parse_ip(hop)
            if ip is None:
                break
            current = ip
            if not self._is_trusted(ip):
                break
        return str(current)


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        limiter: InMemoryRateLimiter,
        *,
        api_prefix: str,
        trust_proxy: bool,
        trusted_proxies: Iterable[str] = (),
    ):
        super().__init__(app)
        self._limiter = limiter
        self._prefix = api_prefix
        self._identity = ClientIdentityResolver(
            trust_proxy=trust_proxy, trusted_proxies=trusted_proxies
        )

    async def dispatch(self, request: Request, call_next):
        route_key = _classify(request.url.path, request.method, self._prefix)
        if route_key is not None:
            client_id = self._identity.resolve(request)
            retry_after = self._limiter.check(route_key, client_id)
            if retry_after is not None:
                rid = getattr(request.state, "request_id", None)
                body = {
                    "type": "https://errors.ioc-enricher.local/rate-limit",
                    "title": "Too many requests",
                    "status": 429,
                    "detail": "Rate limit exceeded. Slow down and try again.",
                    "instance": request.url.path,
                    "request_id": rid,
                    "retry_after_seconds": retry_after,
                }
                return JSONResponse(
                    status_code=429,
                    content=body,
                    media_type=_PROBLEM_MEDIA_TYPE,
                    headers={"Retry-After": str(retry_after)},
                )
        return await call_next(request)
