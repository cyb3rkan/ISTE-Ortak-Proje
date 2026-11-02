"""``POST /enrich`` and ``POST /enrich/batch``."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from ....web.schemas import (
    BatchEnrichRequest,
    BatchEnrichResponse,
    EnrichmentDTO,
    EnrichRequest,
)
from ....web.service import EnrichmentService
from ..deps import get_enrichment_service
from ..security.user_auth import require_api_key_or_user

router = APIRouter(tags=["enrich"], dependencies=[Depends(require_api_key_or_user)])


@router.post(
    "/enrich",
    response_model=EnrichmentDTO,
    response_model_exclude_none=False,
    summary="Enrich a single IOC",
)
def enrich_single(
    payload: EnrichRequest,
    service: EnrichmentService = Depends(get_enrichment_service),
) -> EnrichmentDTO:
    # Adapter-level ValidationError / EnrichmentExecutionError are caught
    # by the global handlers in ``errors.py``.
    return service.enrich_single(payload)


@router.post(
    "/enrich/batch",
    response_model=BatchEnrichResponse,
    response_model_exclude_none=False,
    summary="Enrich a batch of IOCs (max 50)",
)
def enrich_batch(
    payload: BatchEnrichRequest,
    service: EnrichmentService = Depends(get_enrichment_service),
) -> BatchEnrichResponse:
    return service.enrich_batch(payload)
