"""``GET /providers``."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from ....web.schemas import ProviderStatusResponse
from ....web.service import EnrichmentService
from ..deps import get_enrichment_service
from ..security.user_auth import require_api_key_or_user

router = APIRouter(
    tags=["providers"], dependencies=[Depends(require_api_key_or_user)]
)


@router.get(
    "/providers",
    response_model=ProviderStatusResponse,
    summary="List provider configuration and runtime status (no secrets)",
)
def list_providers(
    service: EnrichmentService = Depends(get_enrichment_service),
) -> ProviderStatusResponse:
    return service.get_provider_status()
