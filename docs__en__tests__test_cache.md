# test_cache

## 1. Purpose

`ioc_enricher/tests/test_cache.py` checks the basic contract of the file
cache (`utils/cache.py`); the lifecycle rules — schema version, expiry,
pruning, size cap, clock skew, permissions — are in
`ioc_enricher/tests/test_cache_lifecycle.py`. See
[Cache System and Report Retention](../features/cache-system.md).

---

## 2. Run

From the repository root, after the editable install:

```bash
python -m pytest ioc_enricher/tests/test_cache.py ioc_enricher/tests/test_cache_lifecycle.py -v
python -m pytest ioc_enricher/tests/test_cache_lifecycle.py -k "prune" -v
```

---

## 3. What is covered

`test_cache.py` — class `TestCache` (9 test functions):

| Test | Checks |
|---|---|
| `test_get_miss_returns_none` | Unknown key → `None` |
| `test_set_then_get` | A stored value comes back |
| `test_overwrite_existing_key` | A second `set()` replaces the entry |
| `test_invalidate_removes_entry` | `invalidate()` removes one entry |
| `test_clear_removes_all` | `clear()` removes every entry |
| `test_expired_entry_returns_none` | An entry past its TTL is a miss |
| `test_disabled_cache_always_miss` | `enabled=False` never stores or returns anything |
| `test_stats_returns_dict` | `stats()` keys |
| `test_values_are_json_serialisable` | Entries are JSON, not pickle |

`test_cache_lifecycle.py` — classes `TestEntries` and `TestPruning` plus two
module-level tests (14 test functions): schema version in every entry;
unusable, broken and expired entries are a miss and are removed; atomic
writes; debug logs without the IOC; owner-only files (POSIX only — skipped on
Windows); pruning of expired files without reading them, size cap oldest
first, only cache-named files, at most once per interval, files vanishing
mid-prune; a legacy entry with an unvalidated AI narrative is never served;
an unreadable entry falls back to a fresh enrichment.

The tests use pytest's `tmp_path`, so nothing is written to the real cache
directory; no network, no keys.

---

## 4. Related tests

- `tests/adapter/test_report_lifecycle.py`, `tests/adapter/test_report_store.py`
  — web report storage and retention.

---

## 5. Related

- [Cache System and Report Retention](../features/cache-system.md)
