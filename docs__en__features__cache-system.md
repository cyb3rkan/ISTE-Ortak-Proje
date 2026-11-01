# Cache System and Report Retention

## 1. Overview

`utils/cache.py` (class `Cache`) stores enrichment results as JSON files so a
repeated IOC does not query the providers again within the TTL. Web reports
saved through the API have their own store and retention (section 6).

`ioc_enricher/tests/test_cache_lifecycle.py` and
`tests/adapter/test_report_lifecycle.py` cover the behaviour described here.

---

## 2. Entries

- Directory: `Config.CACHE_DIR` — `ioc_enricher/data/cache/` in a source
  checkout, `$IOC_ENRICHER_DATA_DIR/cache` when `IOC_ENRICHER_DATA_DIR` is
  set (the Docker stack uses `/app/data`).
- One file per IOC, named `<sha256(IOC)>.json` (64 hex characters): the IOC
  value never appears in a file name.
- Content: `{"schema": 2, "cached_at": <epoch seconds>, "value": <result>}`.
- Writes are atomic (temporary file + rename in the same directory). On POSIX
  the directory is owner-only (`0700`) and files `0600`.
- Debug log lines name entries by a keyed fingerprint, never by the IOC.

A **cache miss** that also deletes the file happens for an entry that is:
expired, of an older schema (for example written before the AI-reply
validation), not a JSON object, half-written, without a value, or dated more
than 5 minutes in the future. Such an entry is never served as a result.

On a hit the enricher re-validates the stored result and recomputes the score
and MITRE mapping; an entry it cannot read is discarded with a warning and a
fresh enrichment runs. Results served from the cache carry `from_cache: true`.

---

## 3. Size and clean-up

| Variable | Default | Meaning |
|---|---|---|
| `ENABLE_CACHE` | `true` | `false`: `get()` always misses, `set()` does nothing. |
| `CACHE_TTL_HOURS` | `24` | Entry lifetime. |
| `CACHE_MAX_SIZE_MB` | `100` (1–100000) | Size limit of the cache directory. |

`set()` triggers a prune at most every 10 minutes (never on every request):
expired files are removed by modification time without being read, then the
oldest entries are removed until the directory is under `CACHE_MAX_SIZE_MB`.
Leftover temporary files older than one hour are removed too. Only
cache-named files directly in the cache directory are ever deleted — the same
holds for `clear()`.

---

## 4. Usage

```bash
python -m ioc_enricher --cache-stats     # entry count, size, TTL, enabled
python -m ioc_enricher --clear-cache     # removes cache entries only
python -m ioc_enricher --ioc 203.0.113.7 --no-cache   # bypass for one run
```

Web API: `GET /api/v1/cache` returns `entries`, `size_bytes`, `ttl_hours`
(`hits`/`misses` are not tracked and stay `null`); `DELETE /api/v1/cache`
needs an admin credential and is rate-limited (`IOC_WEB_CLEAR_CACHE_PER_MIN`,
default 1).

```python
from ioc_enricher.utils.cache import Cache

cache = Cache(cache_dir="data/cache", ttl_hours=12, enabled=True, max_size_mb=50)
cache.set("203.0.113.7", {"example": True})
cache.get("203.0.113.7")        # the value, or None
cache.invalidate("203.0.113.7")
cache.stats()                   # {"entry_count", "total_size_kb", "ttl_hours", "enabled"}
cache.prune()                   # {"expired": n, "over_quota": m}
cache.clear()                   # number of removed entries
```

---

## 5. Security notes

| Risk | Control | Limit |
|---|---|---|
| IOC in file names | SHA-256 file names | The IOC is still inside the file. |
| Tampered entry | Schema/type checks; unreadable entries are discarded | An attacker who can write the directory can still plant a well-formed result — keep it owner-only. |
| Stale or legacy content | Expiry, schema version, AI-reply validation before the cache | — |
| Disk exhaustion | `CACHE_MAX_SIZE_MB` prune | Pruning runs only when results are written. |

Cache files contain provider results for investigated IOCs: treat the
directory as sensitive data.

---

## 6. Report storage and retention

| Store | Location | Name | Retention |
|---|---|---|---|
| Web reports (`save_report_format` in API requests) | `<REPORTS_DIR>/web/` | `<UUID>.json`, or `<UUID>.md` with a `<UUID>.md.meta.json` side file | `REPORT_RETENTION_DAYS` (default `30`) and `REPORT_MAX_TOTAL_MB` (default `200`, oldest removed first) |
| CLI reports (`--save`) | `<REPORTS_DIR>/` | `ioc_<type>_<YYYYMMDDTHHMMSSZ>_<8 hex>.<ext>` | **None** — not pruned automatically |

`<REPORTS_DIR>` is `ioc_enricher/reports/` in a source checkout, or the
directory in `IOC_ENRICHER_REPORTS_DIR` when set (the Docker stack uses
`/app/reports`).

Web reports: the caller never chooses a file name (a UUID4 id is generated),
the stored content is the same safe DTO the API returns, each report carries a
schema version and is validated when read, writes are atomic and owner-only
(POSIX), and pruning runs from `save_report` at most hourly, touching only
UUID-named report files.

CLI reports never contain the raw IOC in the name, are created owner-only
(POSIX) and never overwrite an existing file (see
[CLI Usage](../cli/usage.md)). Remove them yourself when they are no longer
needed.

---

## 7. Related

- [Enrichment Engine](enrichment-engine.md)
- [CLI Usage](../cli/usage.md)
- [Security Considerations](../security/considerations.md)
