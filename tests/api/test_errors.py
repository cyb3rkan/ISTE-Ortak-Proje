"""Global error-shape tests."""
from __future__ import annotations

from fastapi.testclient import TestClient


class TestErrorShape:
    def test_404_uses_problem_format(self, client: TestClient) -> None:
        r = client.get("/api/v1/does-not-exist")
        assert r.status_code == 404
        body = r.json()
        for key in ("type", "title", "status", "detail", "instance", "request_id"):
            assert key in body
        assert body["status"] == 404

    def test_405_method_not_allowed(self, client: TestClient) -> None:
        r = client.put("/api/v1/health")
        assert r.status_code == 405
        body = r.json()
        assert body["status"] == 405

    def test_422_validation_uses_problem_format(self, client: TestClient) -> None:
        r = client.post("/api/v1/enrich", json={})
        assert r.status_code == 422
        body = r.json()
        assert body["status"] == 422
        assert "errors" in body
