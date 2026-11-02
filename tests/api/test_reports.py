"""``GET /api/v1/reports/{report_id}``."""
from __future__ import annotations

from fastapi.testclient import TestClient

from .conftest import FakeService  # type: ignore


_UUID = "11111111-1111-4111-8111-111111111111"


class TestReports:
    def test_found(self, client: TestClient, fake_service: FakeService) -> None:
        fake_service.add_report(
            _UUID,
            {
                "report_id": _UUID,
                "format": "json",
                "content": {"hello": "world"},
                "metadata": {},
                "created_at": None,
            },
        )
        r = client.get(f"/api/v1/reports/{_UUID}")
        assert r.status_code == 200
        body = r.json()
        assert body["report_id"] == _UUID
        assert body["format"] == "json"

    def test_missing_returns_404(self, client: TestClient) -> None:
        r = client.get(f"/api/v1/reports/{_UUID}")
        assert r.status_code == 404

    def test_traversal_rejected(self, client: TestClient) -> None:
        # Path regex on the route means traversal attempts never reach the
        # handler — they 404 because no route matches.
        r = client.get("/api/v1/reports/..%2F..%2Fetc%2Fpasswd")
        assert r.status_code in (404, 422)

    def test_non_uuid_rejected(self, client: TestClient) -> None:
        r = client.get("/api/v1/reports/not-a-uuid")
        # FastAPI returns 422 when a path-pattern constraint fails.
        assert r.status_code == 422
