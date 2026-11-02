"""In-memory rate limiter behaviour."""
from __future__ import annotations

from .conftest import FakeService, build_client


class TestRateLimit:
    def test_enrich_over_limit_returns_429(self, fake_service: FakeService) -> None:
        client = build_client(
            fake_service, rate_limit_enabled=True, rate_limit_per_minute=2
        )
        r1 = client.post("/api/v1/enrich", json={"ioc": "1.1.1.1"})
        r2 = client.post("/api/v1/enrich", json={"ioc": "1.1.1.2"})
        r3 = client.post("/api/v1/enrich", json={"ioc": "1.1.1.3"})
        assert r1.status_code == 200
        assert r2.status_code == 200
        assert r3.status_code == 429
        body = r3.json()
        assert body["status"] == 429
        assert "retry_after_seconds" in body
        assert r3.headers.get("retry-after")

    def test_batch_limit_separate_bucket(self, fake_service: FakeService) -> None:
        client = build_client(
            fake_service,
            rate_limit_enabled=True,
            rate_limit_per_minute=10,
            batch_rate_limit_per_minute=1,
        )
        b1 = client.post("/api/v1/enrich/batch", json={"iocs": ["1.1.1.1"]})
        b2 = client.post("/api/v1/enrich/batch", json={"iocs": ["1.1.1.1"]})
        # enrich bucket is independent.
        s1 = client.post("/api/v1/enrich", json={"ioc": "1.1.1.1"})
        assert b1.status_code == 200
        assert b2.status_code == 429
        assert s1.status_code == 200

    def test_health_not_throttled(self, fake_service: FakeService) -> None:
        client = build_client(
            fake_service, rate_limit_enabled=True, rate_limit_per_minute=1
        )
        for _ in range(5):
            assert client.get("/api/v1/health").status_code == 200

    def test_clear_cache_rate_limited(self, fake_service: FakeService) -> None:
        client = build_client(
            fake_service, rate_limit_enabled=True, clear_cache_per_minute=1
        )
        a = client.delete("/api/v1/cache?confirm=true")
        b = client.delete("/api/v1/cache?confirm=true")
        assert a.status_code == 200
        assert b.status_code == 429
