"""Fixtures for the security test suite."""
from __future__ import annotations

import secrets

import pytest
from fastapi.testclient import TestClient

from ioc_enricher.web.api.app import create_app
from ioc_enricher.web.api.deps import get_enrichment_service
from ioc_enricher.web.settings import WebSettings

from ..conftest import FakeService  # noqa: F401

# With no auth mode configured the API fails closed, so build_client uses
# API-key auth and every request carries a valid key and admin key.
_API_KEY = "test-api-key-" + secrets.token_urlsafe(24)
_ADMIN_API_KEY = "test-admin-key-" + secrets.token_urlsafe(24)
AUTH_HEADERS = {"X-API-Key": _API_KEY, "X-Admin-API-Key": _ADMIN_API_KEY}


@pytest.fixture()
def fake_service() -> FakeService:
    return FakeService()


def build_client(
    fake_service: FakeService,
    *,
    rate_limit_enabled: bool = False,
    rate_limit_per_minute: int = 2,
    batch_rate_limit_per_minute: int = 2,
    clear_cache_per_minute: int = 1,
    max_body_bytes: int = 256 * 1024,
    cors_origins=None,
) -> TestClient:
    settings = WebSettings(
        rate_limit_enabled=rate_limit_enabled,
        rate_limit_per_minute=rate_limit_per_minute,
        batch_rate_limit_per_minute=batch_rate_limit_per_minute,
        clear_cache_per_minute=clear_cache_per_minute,
        max_request_body_bytes=max_body_bytes,
        cors_allowed_origins=cors_origins
        if cors_origins is not None
        else ["http://localhost:5173"],
        auth_enabled=True,
        api_keys=[_API_KEY],
        admin_api_keys=[_ADMIN_API_KEY],
    )
    app = create_app(settings)
    app.dependency_overrides[get_enrichment_service] = lambda: fake_service
    return TestClient(app, raise_server_exceptions=False, headers=AUTH_HEADERS)
