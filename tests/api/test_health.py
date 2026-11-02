"""``GET /api/v1/health``."""
from __future__ import annotations

from fastapi.testclient import TestClient

from ..conftest import FakeService


class TestHealth:
    def test_returns_ok(self, client: TestClient) -> None:
        r = client.get("/api/v1/health")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"
        assert body["service"] == "ioc-enricher"
        assert "version" in body
        assert "providers_configured" in body
        assert "ai_enabled" in body

    def test_no_secret_fields(self, client: TestClient) -> None:
        r = client.get("/api/v1/health")
        text = r.text.lower()
        for needle in ("api_key", "apikey", "secret", "token", "password"):
            assert needle not in text

    def test_ai_enabled_is_a_plain_boolean(self, client: TestClient) -> None:
        # Health must expose only ai_enabled true/false — never the provider
        # name, model id, base URL or any AI key.
        body = client.get("/api/v1/health").json()
        assert isinstance(body["ai_enabled"], bool)
        text = client.get("/api/v1/health").text.lower()
        for needle in ("groq", "openai", "gsk-", "sk-", "model", "base_url"):
            assert needle not in text

    def test_request_id_header_present(self, client: TestClient) -> None:
        r = client.get("/api/v1/health")
        assert r.headers.get("x-request-id")

    def test_ai_enabled_true_when_groq_configured(
        self, client: TestClient, fake_service: FakeService
    ) -> None:
        # When the Groq AI layer is genuinely configured, /health reports
        # ai_enabled=true — and still leaks no key, model or base URL.
        fake_service.set_ai_enabled(True)
        body = client.get("/api/v1/health").json()
        assert body["ai_enabled"] is True
        text = client.get("/api/v1/health").text.lower()
        for needle in ("groq", "gsk-", "model", "base_url", "api_key"):
            assert needle not in text

    def test_ai_enabled_false_when_groq_not_configured(
        self, client: TestClient, fake_service: FakeService
    ) -> None:
        # AI_PROVIDER=disabled / no Groq key -> ai_enabled must be false.
        fake_service.set_ai_enabled(False)
        body = client.get("/api/v1/health").json()
        assert body["ai_enabled"] is False
