"""
Error responses must not leak internals.

Specifically:
* No Python traceback markers.
* No filesystem paths.
* No secret-looking strings.
"""
from __future__ import annotations

from .conftest import FakeService, build_client

_SECRET_SHAPED_VALUE = "s" + "k-" + "LEAKED1234567890abcdef"

_LEAK_PATTERNS = [
    "Traceback",
    "File \"",
    "/home/",
    "/opt/",
    "C:\\Users",
    "sk-",
    "AKIA",
    "ghp_",
]


def _build_with_execution_error(fake_service: FakeService):
    fake_service.raise_execution_for("BOOM")
    return build_client(fake_service)


class TestErrorLeakage:
    def test_execution_error_is_clean(self, fake_service: FakeService) -> None:
        client = _build_with_execution_error(fake_service)
        r = client.post("/api/v1/enrich", json={"ioc": "BOOM"})
        assert r.status_code == 502
        text = r.text
        for needle in _LEAK_PATTERNS:
            assert needle not in text

    def test_404_has_no_leakage(self, fake_service: FakeService) -> None:
        client = build_client(fake_service)
        r = client.get("/api/v1/no-such-route")
        for needle in _LEAK_PATTERNS:
            assert needle not in r.text

    def test_validation_error_has_no_leakage(self, fake_service: FakeService) -> None:
        client = build_client(fake_service)
        # Force a Pydantic-level validation failure by supplying a secret-shaped
        # value where a known enum is required. The handler explicitly drops
        # the ``input`` field from each error, so the secret-shaped string must
        # NOT appear in the rendered response.
        r = client.post(
            "/api/v1/enrich",
            json={
                "ioc": "8.8.8.8",
                "ioc_type": _SECRET_SHAPED_VALUE,
            },
        )
        assert r.status_code == 422
        assert _SECRET_SHAPED_VALUE not in r.text
