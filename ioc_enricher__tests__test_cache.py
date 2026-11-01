"""
Tests for ioc_enricher.utils.cache
"""
import time
import pytest
from pathlib import Path

from ioc_enricher.utils.cache import Cache


@pytest.fixture
def tmp_cache(tmp_path: Path) -> Cache:
    return Cache(cache_dir=tmp_path, ttl_hours=1, enabled=True)


class TestCache:

    def test_get_miss_returns_none(self, tmp_cache: Cache):
        assert tmp_cache.get("nonexistent") is None

    def test_set_then_get(self, tmp_cache: Cache):
        tmp_cache.set("key1", {"score": 42})
        result = tmp_cache.get("key1")
        assert result == {"score": 42}

    def test_overwrite_existing_key(self, tmp_cache: Cache):
        tmp_cache.set("key1", {"a": 1})
        tmp_cache.set("key1", {"a": 2})
        assert tmp_cache.get("key1") == {"a": 2}

    def test_invalidate_removes_entry(self, tmp_cache: Cache):
        tmp_cache.set("key2", "value")
        tmp_cache.invalidate("key2")
        assert tmp_cache.get("key2") is None

    def test_clear_removes_all(self, tmp_cache: Cache):
        for i in range(5):
            tmp_cache.set(f"key{i}", i)
        removed = tmp_cache.clear()
        assert removed == 5
        for i in range(5):
            assert tmp_cache.get(f"key{i}") is None

    def test_expired_entry_returns_none(self, tmp_path: Path):
        cache = Cache(cache_dir=tmp_path, ttl_hours=0, enabled=True)
        # ttl_hours=0 → ttl=0 seconds → always expired
        cache.set("expkey", "value")
        # Manually set cached_at to the past
        import json
        path = list(tmp_path.glob("*.json"))[0]
        entry = json.loads(path.read_text())
        entry["cached_at"] = time.time() - 7200  # 2 hours ago
        path.write_text(json.dumps(entry))
        assert cache.get("expkey") is None

    def test_disabled_cache_always_miss(self, tmp_path: Path):
        cache = Cache(cache_dir=tmp_path, enabled=False)
        cache.set("k", "v")
        assert cache.get("k") is None

    def test_stats_returns_dict(self, tmp_cache: Cache):
        tmp_cache.set("a", 1)
        stats = tmp_cache.stats()
        assert stats["entry_count"] >= 1
        assert "ttl_hours" in stats

    def test_values_are_json_serialisable(self, tmp_cache: Cache):
        data = {"nested": {"list": [1, 2, 3], "flag": True}}
        tmp_cache.set("complex", data)
        assert tmp_cache.get("complex") == data
