"""``POST /api/v1/enrich``."""
from __future__ import annotations

from fastapi.testclient import TestClient

from .conftest import FakeService  # type: ignore  # local fixture import


class TestEnrich:
    def test_happy_path(self, client: TestClient, fake_service: FakeService) -> None:
        r = client.post("/api/v1/enrich", json={"ioc": "8.8.8.8"})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["ioc"] == "8.8.8.8"
        assert body["ioc_type"] == "ipv4"
        assert body["risk"]["score"] == 10
        assert len(fake_service.enrich_calls) == 1

    def test_invalid_payload_422(self, client: TestClient) -> None:
        r = client.post("/api/v1/enrich", json={"ioc": "   "})
        assert r.status_code == 422
        body = r.json()
        assert body["status"] == 422
        assert "request_id" in body

    def test_unknown_ioc_type_422(self, client: TestClient) -> None:
        r = client.post(
            "/api/v1/enrich", json={"ioc": "8.8.8.8", "ioc_type": "ipv5"}
        )
        assert r.status_code == 422

    def test_overlong_ioc_422(self, client: TestClient) -> None:
        r = client.post("/api/v1/enrich", json={"ioc": "a" * 4000})
        assert r.status_code == 422

    def test_unknown_save_format_422(self, client: TestClient) -> None:
        r = client.post(
            "/api/v1/enrich",
            json={"ioc": "8.8.8.8", "save_report_format": "pdf"},
        )
        assert r.status_code == 422

    def test_validation_error_from_adapter(
        self, client: TestClient, fake_service: FakeService
    ) -> None:
        fake_service.raise_validation_for("badioc")
        r = client.post("/api/v1/enrich", json={"ioc": "badioc"})
        assert r.status_code == 422
        body = r.json()
        # RFC 7807 shape + non-empty title, locale-independent.
        assert body["status"] == 422
        assert body["type"].endswith("/validation")
        assert isinstance(body["title"], str) and body["title"].strip()
        assert "request_id" in body

    def test_execution_error_from_adapter(
        self, client: TestClient, fake_service: FakeService
    ) -> None:
        fake_service.raise_execution_for("boom")
        r = client.post("/api/v1/enrich", json={"ioc": "boom"})
        assert r.status_code == 502
        body = r.json()
        assert body["status"] == 502
        assert body["type"].endswith("/enrichment")
        assert isinstance(body["title"], str) and body["title"].strip()
        assert body["request_id"]
