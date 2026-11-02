"""``GET /health`` — liveness + safe runtime fingerprint."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from ....web.service import EnrichmentService
from ....web.settings import WebSettings
from ..deps import get_enrichment_service, get_settings
from ..security.user_auth import require_api_key_or_user

router = APIRouter(tags=["health"])


def _maybe_require_auth(
    request: Request,
    settings: WebSettings = Depends(get_settings),
) -> None:
    """
    Conditional gate for the health endpoint.

    Health is public by default (``allow_health_without_auth=True``); when an
    operator pins it to ``False`` it follows the standard combined dependency
    (API key OR user JWT) — so with no auth mode configured it fails closed
    instead of silently staying public. We never surface the configured key
    value to clients via timing differences.
    """
    if settings.allow_health_without_auth:
        return None
    # Delegate to the canonical dependency with the same settings instance.
    require_api_key_or_user(request=request, settings=settings)
    return None


@router.get(
    "/health",
    summary="Service health and capability snapshot",
    dependencies=[Depends(_maybe_require_auth)],
)
def health(
    settings: WebSettings = Depends(get_settings),
    service: EnrichmentService = Depends(get_enrichment_service),
) -> dict:
    status = service.get_provider_status()
    configured = sum(1 for p in status.providers if p.configured)
    return {
        "status": "ok",
        "service": "ioc-enricher",
        "version": settings.app_version,
        "providers_configured": configured,
        "ai_enabled": status.ai_enabled,
    }
