"""``GET /api/v1/providers``."""
from __future__ import annotations

from fastapi.testclient import TestClient


class TestProviders:
    def test_no_secrets(self, client: TestClient) -> None:
        r = client.get("/api/v1/providers")
        assert r.status_code == 200
        text = r.text.lower()
        for needle in ("sk-", "akia", "ghp_", "api_key=", "secret=", "password"):
            assert needle not in text

    def test_shape(self, client: TestClient) -> None:
        r = client.get("/api/v1/providers")
        body = r.json()
        assert "providers" in body
        assert "ai_enabled" in body
        assert isinstance(body["providers"], list)
        assert all(
            set(p.keys()) == {"name", "enabled", "configured", "status", "last_error"}
            for p in body["providers"]
        )
