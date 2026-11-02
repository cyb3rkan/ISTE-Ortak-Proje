"""``POST /api/v1/enrich/batch``."""
from __future__ import annotations

from fastapi.testclient import TestClient

from .conftest import FakeService  # type: ignore


class TestBatch:
    def test_happy_path(self, client: TestClient, fake_service: FakeService) -> None:
        r = client.post(
            "/api/v1/enrich/batch", json={"iocs": ["1.1.1.1", "8.8.8.8"]}
        )
        assert r.status_code == 200
        body = r.json()
        assert body["summary"]["total"] == 2
        assert body["summary"]["success"] == 2
        assert body["summary"]["failed"] == 0

    def test_dedup(self, client: TestClient) -> None:
        r = client.post(
            "/api/v1/enrich/batch",
            json={"iocs": ["1.1.1.1", "1.1.1.1", "8.8.8.8"]},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["summary"]["unique"] == 2
        assert body["summary"]["duplicates_removed"] == 1

    def test_partial_failure(
        self, client: TestClient, fake_service: FakeService
    ) -> None:
        fake_service.raise_validation_for("bad")
        r = client.post(
            "/api/v1/enrich/batch",
            json={"iocs": ["1.1.1.1", "bad", "8.8.8.8"]},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["summary"]["success"] == 2
        assert body["summary"]["failed"] == 1
        assert body["errors"][0]["error_type"] == "validation_error"
        assert body["errors"][0]["ioc"] == "bad"

    def test_over_limit_422(self, client: TestClient) -> None:
        r = client.post(
            "/api/v1/enrich/batch",
            json={"iocs": [f"1.1.1.{i}" for i in range(0, 51)]},
        )
        assert r.status_code == 422

    def test_empty_list_422(self, client: TestClient) -> None:
        r = client.post("/api/v1/enrich/batch", json={"iocs": []})
        assert r.status_code == 422


class TestBatchInputFuzzing:
    """Batch/single endpoint'lere kötü niyetli input denemeleri."""

    def test_oversized_ioc_in_batch_rejected(self, client: TestClient) -> None:
        """2048 karakterden uzun IOC reddedilmeli."""
        long_ioc = "A" * 2049
        r = client.post("/api/v1/enrich/batch", json={"iocs": [long_ioc]})
        assert r.status_code == 422

    def test_batch_exceeds_max_size_rejected(self, client: TestClient) -> None:
        """50'den fazla IOC içeren batch reddedilmeli."""
        iocs = [f"1.1.1.{i}" for i in range(51)]
        r = client.post("/api/v1/enrich/batch", json={"iocs": iocs})
        assert r.status_code == 422

    def test_null_ioc_in_batch_rejected(self, client: TestClient) -> None:
        """Batch'te null değer reddedilmeli."""
        r = client.post("/api/v1/enrich/batch", json={"iocs": [None]})
        assert r.status_code == 422

    def test_empty_string_ioc_rejected(self, client: TestClient) -> None:
        """Boş string IOC batch'te tek değer ise reddedilmeli."""
        r = client.post("/api/v1/enrich/batch", json={"iocs": [""]})
        assert r.status_code == 422

    def test_oversized_single_ioc_rejected(self, client: TestClient) -> None:
        """Single endpoint'te 2048+ karakter reddedilmeli."""
        r = client.post(
            "/api/v1/enrich", json={"ioc": "A" * 2049}
        )
        assert r.status_code == 422

    def test_empty_single_ioc_rejected(self, client: TestClient) -> None:
        """Single endpoint'te boş string reddedilmeli."""
        r = client.post("/api/v1/enrich", json={"ioc": "   "})
        assert r.status_code == 422

    def test_invalid_ioc_type_rejected(self, client: TestClient) -> None:
        """Geçersiz ioc_type reddedilmeli."""
        r = client.post(
            "/api/v1/enrich", json={"ioc": "1.1.1.1", "ioc_type": "../etc/passwd"}
        )
        assert r.status_code == 422

    def test_extra_fields_rejected(self, client: TestClient) -> None:
        """Beklenmeyen alanlar (extra='forbid') reddedilmeli."""
        r = client.post(
            "/api/v1/enrich",
            json={"ioc": "1.1.1.1", "__proto__": {"role": "admin"}},
        )
        assert r.status_code == 422

    def test_path_traversal_pattern_passes_schema_then_validation(
        self, client: TestClient, fake_service
    ) -> None:
        """Path traversal pattern schema'yı geçer ama servis validation_error döndürmeli."""
        bad = "../../../etc/passwd"
        fake_service.raise_validation_for(bad)
        r = client.post("/api/v1/enrich", json={"ioc": bad})
        assert r.status_code in (400, 422)

    def test_sql_injection_pattern_passes_schema_then_validation(
        self, client: TestClient, fake_service
    ) -> None:
        """SQL injection pattern schema'yı geçer ama servis validation_error döndürmeli."""
        bad = "' OR '1'='1"
        fake_service.raise_validation_for(bad)
        r = client.post("/api/v1/enrich", json={"ioc": bad})
        assert r.status_code in (400, 422)
