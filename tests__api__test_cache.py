"""``GET /api/v1/cache`` and ``DELETE /api/v1/cache``."""
from __future__ import annotations

from fastapi.testclient import TestClient

from .conftest import FakeService  # type: ignore


class TestCacheStats:
    def test_returns_stats_only(self, client: TestClient) -> None:
        r = client.get("/api/v1/cache")
        assert r.status_code == 200
        body = r.json()
        assert "entries" in body
        # No IOC values, no cache keys.
        text = r.text.lower()
        for needle in ("ioc", "iocs", "cache_keys"):
            assert needle not in text


class TestClearCache:
    def test_requires_confirm(self, client: TestClient) -> None:
        r = client.delete("/api/v1/cache")
        assert r.status_code == 400
        assert "confirm" in r.text.lower()

    def test_confirm_true_clears(
        self, client: TestClient, fake_service: FakeService
    ) -> None:
        r = client.delete("/api/v1/cache?confirm=true")
        assert r.status_code == 200
        body = r.json()
        assert body["cleared"] is True
        assert body["removed_entries"] == 3
        assert fake_service.clear_cache_calls == 1

    def test_confirm_false_rejected(self, client: TestClient) -> None:
        r = client.delete("/api/v1/cache?confirm=false")
        assert r.status_code == 400
