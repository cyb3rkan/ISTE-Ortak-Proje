"""
JSON file-based cache for IOC enrichment results.

Each IOC gets its own cache file named by a SHA-256 hash of the
indicator value (the value itself is never a file name). Entries are
written atomically, carry a schema version and expire after a
configurable TTL:

* An entry that is expired, from an older schema (for instance written
  before the AI-narrative validation), unreadable, half-written or dated in
  the future is a cache miss and is deleted — never served as a result.
* Expired files and the total size (``CACHE_MAX_SIZE_MB``) are pruned from
  ``set()`` at most every ``PRUNE_INTERVAL_SECONDS``, never on every
  request. Only cache-named files directly in the cache directory are
  ever deleted.

Usage:
    from ioc_enricher.utils.cache import Cache

    cache = Cache()
    data = cache.get("8.8.8.8")     # None if not cached / expired
    cache.set("8.8.8.8", result)
    cache.invalidate("8.8.8.8")
    cache.clear()
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .config import Config
from .fileio import TEMP_SUFFIX, atomic_write_text, private_dir
from .logger import get_logger, ioc_ref

log = get_logger(__name__)

#: Bump when the meaning of cached values changes: older entries become misses.
CACHE_SCHEMA_VERSION = 2
#: ``set()`` prunes the cache directory at most this often.
PRUNE_INTERVAL_SECONDS = 600.0

_CLOCK_SKEW_SECONDS = 300.0
_STALE_TEMP_SECONDS = 3600.0
_ENTRY_NAME = re.compile(r"^[0-9a-f]{64}\.json$")
_TEMP_NAME = re.compile(r"^\.[0-9a-f]{64}\.json\..+" + re.escape(TEMP_SUFFIX) + r"$")


class Cache:
    """
    Thread-safe, file-backed key-value cache with TTL expiry.

    Args:
        cache_dir:   Directory for cache files (default: Config.CACHE_DIR).
        ttl_hours:   Expiry time in hours (default: Config.CACHE_TTL_HOURS).
        enabled:     When False every operation is a no-op (default: Config.ENABLE_CACHE).
        max_size_mb: Size limit of the cache directory (default: Config.CACHE_MAX_SIZE_MB).
        clock:       Wall clock (injectable for tests).
    """

    def __init__(
        self,
        cache_dir: Optional[Path] = None,
        ttl_hours: Optional[int] = None,
        enabled: Optional[bool] = None,
        max_size_mb: Optional[int] = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._dir = Path(cache_dir or Config.CACHE_DIR)
        self._ttl = (ttl_hours if ttl_hours is not None else Config.CACHE_TTL_HOURS) * 3600
        self._enabled = enabled if enabled is not None else Config.ENABLE_CACHE
        size_mb = Config.CACHE_MAX_SIZE_MB if max_size_mb is None else max_size_mb
        self._max_bytes = max(1, int(size_mb)) * 1024 * 1024
        self._clock = clock
        self._last_prune: Optional[float] = None
        self._prune_lock = threading.Lock()
        if self._enabled:
            private_dir(self._dir)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, key: str) -> Optional[Any]:
        """
        Return cached value for *key*, or ``None`` if absent / expired /
        unusable (an unusable entry is deleted).

        Args:
            key: Cache key (usually the raw IOC string).
        """
        if not self._enabled:
            return None

        path = self._path(key)
        try:
            raw = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        except (OSError, UnicodeDecodeError) as exc:
            log.warning("Unreadable cache entry for %s (%s); treated as a miss.",
                        ioc_ref(key), type(exc).__name__)
            self._remove(path)
            return None

        problem, value = self._check(raw)
        if problem == "expired":
            log.debug("Cache expired for %s", ioc_ref(key))
        elif problem:
            log.warning("Discarding cache entry for %s: %s.", ioc_ref(key), problem)
        if problem:
            self._remove(path)
            return None
        log.debug("Cache hit for %s", ioc_ref(key))
        return value

    def set(self, key: str, value: Any) -> None:
        """
        Store *value* under *key*.

        Args:
            key:   Cache key.
            value: JSON-serialisable object.
        """
        if not self._enabled:
            return

        self._maybe_prune()
        entry = {"schema": CACHE_SCHEMA_VERSION, "cached_at": self._clock(), "value": value}
        try:
            private_dir(self._dir)
            atomic_write_text(
                self._path(key), json.dumps(entry, ensure_ascii=False, default=str)
            )
            log.debug("Cached result for %s", ioc_ref(key))
        except OSError as exc:
            log.warning("Failed to write cache entry for %s (%s).", ioc_ref(key), type(exc).__name__)

    def invalidate(self, key: str) -> None:
        """Remove the cache entry for *key* if it exists."""
        self._remove(self._path(key))

    def clear(self) -> int:
        """Delete all cache entries.  Returns the number of files removed."""
        removed = sum(1 for path in self._cache_files() if self._remove(path))
        log.info("Cache cleared — %d file(s) removed", removed)
        return removed

    def prune(self) -> Dict[str, int]:
        """
        Delete expired entries (by file age) and then, while the cache is
        larger than its size limit, the oldest ones. Leftovers of interrupted
        writes go too. Only cache-named files directly in the cache directory
        are considered; a file that vanishes meanwhile is skipped.
        """
        removed = {"expired": 0, "over_quota": 0}
        now = self._clock()
        kept: List[Tuple[float, int, Path]] = []
        for path in self._cache_files():
            try:
                stat = path.stat()
            except OSError:
                continue
            if now - stat.st_mtime > self._ttl:
                removed["expired"] += self._remove(path)
            else:
                kept.append((stat.st_mtime, stat.st_size, path))

        total = sum(size for _, size, _ in kept)
        for _, size, path in sorted(kept, key=lambda item: item[0]):
            if total <= self._max_bytes:
                break
            if self._remove(path):
                removed["over_quota"] += 1
                total -= size

        self._remove_stale_temps(now)
        if removed["expired"] or removed["over_quota"]:
            log.info("Cache pruned — %d expired, %d over the size limit.",
                     removed["expired"], removed["over_quota"])
        return removed

    def stats(self) -> dict[str, Any]:
        """Return simple statistics about the cache directory."""
        files = self._cache_files()
        total_bytes = 0
        for path in files:
            try:
                total_bytes += path.stat().st_size
            except OSError:
                pass
        return {
            "entry_count": len(files),
            "total_size_kb": round(total_bytes / 1024, 1),
            "ttl_hours": self._ttl / 3600,
            "enabled": self._enabled,
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _check(self, raw: str) -> Tuple[Optional[str], Any]:
        """``(problem, value)``: *problem* is None for a usable entry."""
        try:
            entry = json.loads(raw)
        except ValueError:
            return "unreadable", None
        if not isinstance(entry, dict):
            return "unreadable", None
        if entry.get("schema") != CACHE_SCHEMA_VERSION:
            return "written by an older version", None
        cached_at = entry.get("cached_at")
        if (
            isinstance(cached_at, bool)
            or not isinstance(cached_at, (int, float))
            or not math.isfinite(cached_at)
        ):
            return "invalid timestamp", None
        if "value" not in entry:
            return "no value", None
        now = self._clock()
        if cached_at > now + _CLOCK_SKEW_SECONDS:
            return "timestamp in the future", None
        if now - cached_at > self._ttl:
            return "expired", None
        return None, entry["value"]

    def _maybe_prune(self) -> None:
        now = self._clock()
        if self._last_prune is not None and now - self._last_prune < PRUNE_INTERVAL_SECONDS:
            return
        if not self._prune_lock.acquire(blocking=False):
            return  # another thread is pruning
        try:
            self._last_prune = now
            self.prune()
        except OSError as exc:
            log.warning("Cache pruning failed (%s).", type(exc).__name__)
        finally:
            self._prune_lock.release()

    def _cache_files(self) -> List[Path]:
        try:
            with os.scandir(self._dir) as entries:
                return [
                    Path(entry.path) for entry in entries
                    if _ENTRY_NAME.match(entry.name) and entry.is_file(follow_symlinks=False)
                ]
        except OSError:
            return []

    def _remove_stale_temps(self, now: float) -> None:
        try:
            with os.scandir(self._dir) as entries:
                temps = [
                    Path(entry.path) for entry in entries
                    if _TEMP_NAME.match(entry.name) and entry.is_file(follow_symlinks=False)
                ]
        except OSError:
            return
        for path in temps:
            try:
                if now - path.stat().st_mtime > _STALE_TEMP_SECONDS:
                    self._remove(path)
            except OSError:
                continue

    @staticmethod
    def _remove(path: Path) -> bool:
        try:
            path.unlink()
            return True
        except FileNotFoundError:
            return False
        except OSError:
            return False

    def _path(self, key: str) -> Path:
        """Return the file path for a cache key."""
        digest = hashlib.sha256(key.encode()).hexdigest()
        return self._dir / f"{digest}.json"
