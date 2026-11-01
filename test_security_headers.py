"""Verify the hardening headers ride on every response."""
from __future__ import annotations

from .conftest import FakeService, build_client


_EXPECTED = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
}


class TestSecurityHeaders:
    def test_present_on_health(self, fake_service: FakeService) -> None:
        client = build_client(fake_service)
        r = client.get("/api/v1/health")
        for k, v in _EXPECTED.items():
            assert r.headers.get(k) == v, f"missing/wrong header: {k}"
        csp = r.headers.get("content-security-policy", "")
        assert "default-src 'self'" in csp
        assert "frame-ancestors 'none'" in csp

    def test_present_on_404(self, fake_service: FakeService) -> None:
        client = build_client(fake_service)
        r = client.get("/api/v1/nope")
        for k, v in _EXPECTED.items():
            assert r.headers.get(k) == v

    def test_request_id_round_trip(self, fake_service: FakeService) -> None:
        client = build_client(fake_service)
        r = client.get("/api/v1/health", headers={"X-Request-ID": "my-trace-id-001"})
        assert r.headers.get("x-request-id") == "my-trace-id-001"

    def test_unsafe_request_id_replaced(self, fake_service: FakeService) -> None:
        client = build_client(fake_service)
        # CRLF injection attempt — must be ignored.
        r = client.get(
            "/api/v1/health",
            headers={"X-Request-ID": "evil\r\nSet-Cookie: pwned=1"},
        )
        assert "\r" not in r.headers.get("x-request-id", "")
        assert r.headers.get("x-request-id") != "evil"
