"""
Disk cache life cycle.

Entries carry a schema version; anything older, broken, half-written or
dated in the future is a cache miss and is removed, never served as a result.
Expired entries and the total size are pruned periodically (not on every
request), only cache-named files are ever deleted, and writes are atomic.
Only fake IOCs and temporary directories are used.
"""
from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path

import pytest

from ioc_enricher.enricher import IOCEnricher
from ioc_enricher.utils import cache as cache_module
from ioc_enricher.utils.cache import Cache
from ioc_enricher.utils.config import Config

_IOC = "203.0.113.7"


class _Clock:
    def __init__(self, now: float = 1_700_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def _cache(tmp_path: Path, **kwargs) -> Cache:
    kwargs.setdefault("ttl_hours", 1)
    kwargs.setdefault("enabled", True)
    return Cache(cache_dir=tmp_path, **kwargs)


def _only_file(tmp_path: Path) -> Path:
    [path] = [p for p in tmp_path.iterdir() if p.suffix == ".json"]
    return path


class TestEntries:

    def test_entries_carry_the_schema_version(self, tmp_path):
        cache = _cache(tmp_path)
        cache.set(_IOC, {"ioc": _IOC})
        entry = json.loads(_only_file(tmp_path).read_text(encoding="utf-8"))
        assert entry["schema"] == cache_module.CACHE_SCHEMA_VERSION
        assert cache.get(_IOC) == {"ioc": _IOC}

    @pytest.mark.parametrize("entry", [
        pytest.param({"cached_at": "TIME", "value": {"ioc": _IOC}}, id="legacy-no-schema"),
        pytest.param({"schema": 1, "cached_at": "TIME", "value": {"ioc": _IOC}}, id="older-schema"),
        pytest.param({"schema": "SCHEMA", "cached_at": "yesterday", "value": {}}, id="text-timestamp"),
        pytest.param({"schema": "SCHEMA", "cached_at": "FUTURE", "value": {}}, id="future-timestamp"),
        pytest.param({"schema": "SCHEMA", "cached_at": "TIME"}, id="no-value"),
        pytest.param(["SCHEMA", "TIME"], id="not-an-object"),
    ])
    def test_unusable_entry_is_a_miss_and_is_removed(self, tmp_path, caplog, entry):
        cache = _cache(tmp_path)
        cache.set(_IOC, {"ioc": _IOC})
        path = _only_file(tmp_path)
        raw = json.dumps(entry).replace('"TIME"', str(time.time())).replace(
            '"FUTURE"', str(time.time() + 86_400)).replace(
            '"SCHEMA"', str(cache_module.CACHE_SCHEMA_VERSION))
        path.write_text(raw, encoding="utf-8")
        with caplog.at_level(logging.DEBUG, logger="ioc_enricher"):
            assert cache.get(_IOC) is None
        assert not path.exists()
        assert _IOC not in caplog.text and str(tmp_path) not in caplog.text

    @pytest.mark.parametrize("raw", ["", "{", '{"schema": 2, "cach', "\x00\x01"])
    def test_broken_file_is_a_miss_and_is_removed(self, tmp_path, raw):
        cache = _cache(tmp_path)
        cache.set(_IOC, {"ioc": _IOC})
        path = _only_file(tmp_path)
        path.write_text(raw, encoding="utf-8")
        assert cache.get(_IOC) is None
        assert not path.exists()

    def test_expired_entry_is_a_miss_and_is_removed(self, tmp_path):
        clock = _Clock()
        cache = _cache(tmp_path, clock=clock)
        cache.set(_IOC, {"ioc": _IOC})
        clock.now += 3601
        assert cache.get(_IOC) is None
        assert not list(tmp_path.glob("*.json"))

    def test_write_is_atomic(self, tmp_path, monkeypatch):
        replaced = []
        real_replace = os.replace

        def spy(src, dst):
            replaced.append((Path(src).parent, Path(dst).name))
            return real_replace(src, dst)

        monkeypatch.setattr(cache_module.os, "replace", spy)
        cache = _cache(tmp_path)
        cache.set(_IOC, {"ioc": _IOC})
        assert replaced and replaced[0][0] == tmp_path
        assert [p.name for p in tmp_path.iterdir()] == [replaced[0][1]]   # no temp left

    def test_debug_logs_do_not_carry_the_ioc(self, tmp_path, caplog):
        cache = _cache(tmp_path)
        with caplog.at_level(logging.DEBUG, logger="ioc_enricher"):
            cache.set(_IOC, {"ioc": _IOC})
            cache.get(_IOC)
        assert "203.0" not in caplog.text and ".113.7" not in caplog.text

    @pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
    def test_files_are_private(self, tmp_path):
        cache_dir = tmp_path / "new-cache"
        cache = Cache(cache_dir=cache_dir, ttl_hours=1, enabled=True)
        cache.set(_IOC, {"ioc": _IOC})
        assert cache_dir.stat().st_mode & 0o777 == 0o700
        assert _only_file(cache_dir).stat().st_mode & 0o777 == 0o600


class TestPruning:

    @staticmethod
    def _age(path: Path, seconds: float) -> None:
        stamp = time.time() - seconds
        os.utime(path, (stamp, stamp))

    def test_prune_removes_expired_files_without_reading_them(self, tmp_path):
        cache = _cache(tmp_path)
        for i in range(4):
            cache.set(f"203.0.113.{i}", {"i": i})
        old = sorted(tmp_path.glob("*.json"))[:2]
        for path in old:
            self._age(path, 2 * 3600)
        removed = cache.prune()
        assert removed["expired"] == 2
        assert len(list(tmp_path.glob("*.json"))) == 2

    def test_prune_enforces_the_size_cap_oldest_first(self, tmp_path):
        cache = _cache(tmp_path, max_size_mb=1)
        blob = "x" * 200_000
        for i in range(8):
            cache.set(f"203.0.113.{i}", {"blob": blob})
            self._age(_newest(tmp_path), 100 - i)       # older first
        newest = _newest(tmp_path)
        cache.prune()
        total = sum(p.stat().st_size for p in tmp_path.glob("*.json"))
        assert total <= 1024 * 1024
        assert newest.exists()

    def test_prune_only_touches_cache_files(self, tmp_path):
        cache = _cache(tmp_path, ttl_hours=0)
        cache.set(_IOC, {"ioc": _IOC})
        foreign = [tmp_path / "notes.json", tmp_path / "README.txt",
                   tmp_path / ("A" * 64 + ".json")]
        for path in foreign:
            path.write_text("keep", encoding="utf-8")
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / ("b" * 64 + ".json")).write_text("keep", encoding="utf-8")
        for path in tmp_path.rglob("*"):
            if path.is_file():
                self._age(path, 3600)
        cache.prune()
        assert all(path.exists() for path in foreign)
        assert (tmp_path / "sub" / ("b" * 64 + ".json")).exists()
        cache.clear()
        assert all(path.exists() for path in foreign)

    def test_prune_runs_from_set_at_most_once_per_interval(self, tmp_path, monkeypatch):
        clock = _Clock()
        cache = _cache(tmp_path, clock=clock)
        calls = []
        monkeypatch.setattr(cache, "prune", lambda: calls.append(clock.now) or {})
        for _ in range(5):
            cache.set(_IOC, {"ioc": _IOC})
        assert len(calls) == 1
        clock.now += cache_module.PRUNE_INTERVAL_SECONDS
        cache.set(_IOC, {"ioc": _IOC})
        assert len(calls) == 2

    def test_files_vanishing_mid_prune_do_not_break_it(self, tmp_path, monkeypatch):
        # Another process removes an entry between the listing and the stat.
        cache = _cache(tmp_path, ttl_hours=0)
        for i in range(3):
            cache.set(f"203.0.113.{i}", {"i": i})
        listed = cache._cache_files()
        for path in listed:
            # Explicitly old: a just-written file's mtime can be a tick ahead of
            # time.time() (coarse file-system clock), so "age 0" is not reliable.
            self._age(path, 10)
        phantom = tmp_path / ("c" * 64 + ".json")
        monkeypatch.setattr(cache, "_cache_files", lambda: [phantom] + listed)
        removed = cache.prune()             # must not raise
        assert removed["expired"] == 3


def _newest(directory: Path) -> Path:
    return max(directory.glob("*.json"), key=lambda p: p.stat().st_mtime_ns)


# ---------------------------------------------------------------------------
# The enricher never serves a stale or broken entry
# ---------------------------------------------------------------------------

class _NoProviders(Config):
    VIRUSTOTAL_API_KEY = ""
    ABUSEIPDB_API_KEY = ""
    SHODAN_API_KEY = ""
    OTX_API_KEY = ""
    GREYNOISE_API_KEY = ""
    ZEROBOUNCE_API_KEY = ""


def _legacy_result(ai_provider: str = "groq") -> dict:
    return {
        "metadata": {"ioc": _IOC, "ioc_type": "ipv4"},
        "risk_assessment": {"score": 99, "level": "CRITICAL"},
        "threat_intelligence": {},
        "mitre_attack": [],
        "ai_analysis": {
            "summary": "UNVALIDATED NARRATIVE from before the AI hardening",
            "provider": ai_provider,
        },
    }


def test_legacy_entry_with_an_unvalidated_narrative_is_not_served(tmp_path):
    cache = _cache(tmp_path)
    cache.set(_IOC, {"placeholder": True})
    path = _only_file(tmp_path)
    path.write_text(json.dumps({"cached_at": time.time(), "value": _legacy_result()}),
                    encoding="utf-8")
    enricher = IOCEnricher(config=_NoProviders, cache=cache, ai_enabled=False)
    result = enricher.enrich(_IOC)
    assert result.from_cache is False
    assert result.ai_analysis is None
    assert "UNVALIDATED" not in path.read_text(encoding="utf-8") if path.exists() else True


def _bad_status() -> dict:
    broken = _legacy_result()
    broken["threat_intelligence"] = {"VirusTotal": {"status": "no-such-status"}}
    return broken


@pytest.mark.parametrize("broken", [
    pytest.param(_bad_status(), id="unknown-provider-status"),
    pytest.param(["not", "a", "result"], id="value-not-object"),
    pytest.param({"risk_assessment": {"level": "NOT-A-LEVEL"}}, id="bad-risk-level"),
])
def test_unreadable_entry_falls_back_to_a_fresh_enrichment(tmp_path, caplog, broken):
    cache = _cache(tmp_path)
    cache.set(_IOC, broken)
    enricher = IOCEnricher(config=_NoProviders, cache=cache, ai_enabled=False)
    with caplog.at_level(logging.WARNING, logger="ioc_enricher"):
        result = enricher.enrich(_IOC)
    assert result.from_cache is False
    assert result.risk_score.score == 0
    assert "cache entry" in caplog.text
    assert _IOC not in caplog.text
