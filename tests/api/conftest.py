"""
Per-package fixtures for the FastAPI integration tests.

We build a *fresh* app from :func:`create_app` for each test so middleware
state (rate-limit counters in particular) doesn't bleed across cases.
"""
from __future__ import annotations

import secrets

import pytest
from fastapi.testclient import TestClient

from ioc_enricher.web.api.app import create_app
from ioc_enricher.web.api.deps import get_enrichment_service
from ioc_enricher.web.settings import WebSettings

from ..conftest import FakeService  # noqa: F401

# With no auth mode configured the API fails closed, so the app is built with
# API-key auth and every request carries a valid key and admin key.
_API_KEY = "test-api-key-" + secrets.token_urlsafe(24)
_ADMIN_API_KEY = "test-admin-key-" + secrets.token_urlsafe(24)
AUTH_HEADERS = {"X-API-Key": _API_KEY, "X-Admin-API-Key": _ADMIN_API_KEY}


@pytest.fixture()
def fake_service() -> FakeService:
    return FakeService()


def _build_app(fake: FakeService, *, rate_limit: bool = False):
    settings = WebSettings(
        rate_limit_enabled=rate_limit,
        # Keep limits small so explicit rate-limit tests can drive them, but
        # tests that just want to make many requests don't trip them.
        rate_limit_per_minute=1000,
        batch_rate_limit_per_minute=1000,
        clear_cache_per_minute=1000,
        auth_enabled=True,
        api_keys=[_API_KEY],
        admin_api_keys=[_ADMIN_API_KEY],
    )
    app = create_app(settings)
    app.dependency_overrides[get_enrichment_service] = lambda: fake
    return app


@pytest.fixture()
def client(fake_service: FakeService) -> TestClient:
    app = _build_app(fake_service, rate_limit=False)
    return TestClient(app, raise_server_exceptions=False, headers=AUTH_HEADERS)
