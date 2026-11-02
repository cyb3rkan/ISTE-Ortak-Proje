"""Body-size middleware tests."""
from __future__ import annotations

import json

from .conftest import FakeService, build_client


class TestBodySizeLimit:
    def test_oversize_via_content_length(self, fake_service: FakeService) -> None:
        client = build_client(fake_service, max_body_bytes=1024)
        # Build a body that is *valid JSON* but well over the limit.
        big_string = "x" * 2048
        payload = json.dumps({"ioc": big_string})
        r = client.post(
            "/api/v1/enrich",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 413
        body = r.json()
        assert body["status"] == 413
        assert body["title"].lower().startswith("payload too large")

    def test_under_limit_is_fine(self, fake_service: FakeService) -> None:
        client = build_client(fake_service, max_body_bytes=4096)
        r = client.post("/api/v1/enrich", json={"ioc": "1.1.1.1"})
        assert r.status_code == 200
