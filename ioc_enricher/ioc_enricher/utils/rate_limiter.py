"""
Token-bucket rate limiter with per-provider configuration.

Each provider gets its own bucket, shared by every thread. A caller reserves
its token under the bucket lock and then waits, outside the lock, for that
token's turn, so concurrent callers queue up one token each instead of all
slipping through after a single sleep. Waiting is bounded: ``wait()`` never
sleeps longer than its budget and answers False instead, so a worker is never
pinned for a whole quota window.

What the limits represent
    A per-minute pacing budget for this process, not the provider's
    subscription quota. VirusTotal's 4/min is the rate of its public (free)
    API; the other providers' 60/min with a burst of 10 are project defaults.
    Daily or weekly quotas depend on the subscription and are not modelled
    here: when one runs out the provider answers HTTP 429, and ``backoff()``
    pauses that provider for its ``Retry-After`` (bounded) or 60 seconds.
    ``PROVIDER_RATE_LIMITS`` overrides the pacing, for example
    ``"VirusTotal=500:10;GreyNoise=30:5"``.

Usage:
    from ioc_enricher.utils.rate_limiter import RateLimiter

    limiter = RateLimiter()
    if limiter.wait("VirusTotal"):       # False: no slot within the budget
        ...                              # send the request
    limiter.backoff("AbuseIPDB", 120)    # after HTTP 429 with Retry-After: 120
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Callable, Dict, Mapping, Optional, Tuple

from .config import Config
from .logger import get_logger

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Per-provider defaults  (requests per minute, burst cap)
# ---------------------------------------------------------------------------

_PROVIDER_LIMITS: Dict[str, Tuple[int, int]] = {
    # (requests_per_minute, burst_cap)
    "VirusTotal": (4, 4),       # Free tier: 4 req/min
    "AbuseIPDB": (60, 10),
    "Shodan": (60, 10),
    "AlienVault OTX": (60, 10),
    "GreyNoise": (60, 10),
    "ZeroBounce": (60, 10),
    "_default": (30, 5),
}

#: Pause after HTTP 429 without a usable ``Retry-After``.
DEFAULT_BACKOFF_SECONDS = 60.0
#: Bounds of one 429 pause, whatever ``Retry-After`` asks for.
MIN_BACKOFF_SECONDS = 1.0
MAX_BACKOFF_SECONDS = 3600.0

_MAX_RPM = 100_000
_MAX_BURST = 10_000


def parse_limits(spec: str) -> Dict[str, Tuple[int, int]]:
    """
    Parse ``"Name=requests_per_minute[:burst];..."``.

    Entries that do not parse, or ask for zero or absurd values, are skipped;
    the burst defaults to ``min(requests_per_minute, 10)``.
    """
    limits: Dict[str, Tuple[int, int]] = {}
    for entry in (spec or "").split(";"):
        name, sep, value = entry.partition("=")
        name = name.strip()
        rpm_text, _, burst_text = value.strip().partition(":")
        try:
            rpm = int(rpm_text)
            burst = int(burst_text) if burst_text else min(rpm, 10)
        except ValueError:
            rpm = burst = 0
        if sep and name and 0 < rpm <= _MAX_RPM and 0 < burst <= _MAX_BURST:
            limits[name] = (rpm, burst)
        elif entry.strip():
            log.warning("Ignoring invalid PROVIDER_RATE_LIMITS entry: %r", entry.strip())
    return limits


def retry_after_seconds(value: object, now: Optional[datetime] = None) -> Optional[float]:
    """
    Seconds requested by a ``Retry-After`` header value: delta-seconds or an
    HTTP-date. ``None`` when absent or unparsable; a date in the past gives 0.
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if text.isascii() and text.isdigit():
        return float(int(text))
    try:
        when = parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    current = now or datetime.now(timezone.utc)
    return max(0.0, (when - current).total_seconds())


@dataclass
class _Bucket:
    """Token-bucket state for one provider; every field is guarded by ``lock``."""

    capacity: float
    refill_rate: float              # tokens per second
    tokens: float
    updated: float                  # clock reading of the last refill
    paused_until: float = 0.0       # no request before this clock reading (HTTP 429)
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def _refill(self, now: float) -> None:
        self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.refill_rate)
        self.updated = now

    def reserve(self, now: float, max_wait: float) -> Optional[float]:
        """
        Take the next token and return how long to wait before using it, or
        ``None`` (nothing taken) when that is longer than *max_wait*. Tokens
        may go negative: each waiting caller holds its own future token.
        """
        with self.lock:
            self._refill(now)
            debt = (1.0 - self.tokens) / self.refill_rate if self.tokens < 1.0 else 0.0
            delay = max(debt, self.paused_until - now, 0.0)
            if delay > max_wait:
                return None
            self.tokens -= 1.0
            return delay

    def pause(self, now: float, seconds: float) -> float:
        """Hold requests back for *seconds*; never shortens a longer pause."""
        with self.lock:
            self._refill(now)
            self.paused_until = max(self.paused_until, now + seconds)
            self.tokens = min(self.tokens, 0.0)
            return self.paused_until - now

    def paused_for(self, now: float) -> float:
        with self.lock:
            return self.paused_until - now


class RateLimiter:
    """
    Thread-safe, per-provider rate limiter.

    Instantiate once and share across threads.

    Args:
        limits:   ``{provider: (requests_per_minute, burst)}`` on top of the
                  defaults; ``None`` reads ``Config.PROVIDER_RATE_LIMITS``.
        max_wait: Longest ``wait()`` may sleep (``Config.RATE_LIMIT_MAX_WAIT_SECONDS``).
        clock / sleep: Injectable for tests.
    """

    def __init__(
        self,
        limits: Optional[Mapping[str, Tuple[int, int]]] = None,
        *,
        max_wait: Optional[float] = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._limits: Dict[str, Tuple[int, int]] = dict(_PROVIDER_LIMITS)
        self._limits.update(
            parse_limits(Config.PROVIDER_RATE_LIMITS) if limits is None else limits
        )
        self._max_wait = Config.RATE_LIMIT_MAX_WAIT_SECONDS if max_wait is None else max_wait
        self._clock = clock
        self._sleep = sleep
        self._buckets: Dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def _get_bucket(self, provider: str) -> _Bucket:
        with self._lock:
            bucket = self._buckets.get(provider)
            if bucket is None:
                rpm, burst = self._limits.get(provider, self._limits["_default"])
                bucket = _Bucket(
                    capacity=float(burst),
                    refill_rate=rpm / 60.0,
                    tokens=float(burst),
                    updated=self._clock(),
                )
                self._buckets[provider] = bucket
            return bucket

    def wait(self, provider: str, max_wait: Optional[float] = None) -> bool:
        """
        Take one request slot for *provider*, sleeping at most *max_wait*
        seconds (never more than the configured budget).

        Returns:
            True once the slot is held: send the request. False when the
            next slot, or the end of a 429 pause, is further away than the
            budget: nothing is sent, the caller reports "rate limited".
        """
        budget = self._max_wait if max_wait is None else max(0.0, min(max_wait, self._max_wait))
        bucket = self._get_bucket(provider)
        start = self._clock()
        delay = bucket.reserve(start, budget)
        if delay is None:
            log.debug("Rate limiter: no %s slot within %.1fs", provider, budget)
            return False
        if delay > 0:
            log.debug("Rate limiter: sleeping %.2fs for %s", delay, provider)
            self._sleep(delay)
        # Another worker may have hit HTTP 429 while this one slept.
        now = self._clock()
        paused = bucket.paused_for(now)
        if paused > 0:
            if now + paused > start + budget:
                return False
            self._sleep(paused)
        return True

    def backoff(self, provider: str, delay: Optional[float] = None) -> float:
        """
        Pause *provider* after HTTP 429 for *delay* seconds (its Retry-After),
        bounded to ``[MIN_BACKOFF_SECONDS, MAX_BACKOFF_SECONDS]``; ``None``
        means ``DEFAULT_BACKOFF_SECONDS``. A shorter delay never cuts an
        active pause short.

        Returns:
            Seconds until the provider may be called again.
        """
        seconds = DEFAULT_BACKOFF_SECONDS if delay is None else float(delay)
        if seconds != seconds:  # NaN
            seconds = DEFAULT_BACKOFF_SECONDS
        seconds = min(max(seconds, MIN_BACKOFF_SECONDS), MAX_BACKOFF_SECONDS)
        paused = self._get_bucket(provider).pause(self._clock(), seconds)
        log.warning("Rate limit hit for %s — pausing %.0fs", provider, paused)
        return paused
