"""
``GET /cache`` and ``DELETE /cache``.

> Security note: ``DELETE /cache`` is an admin operation. It accepts a valid
> admin API key (server-to-server) or a user JWT carrying the admin role.
> It additionally requires ``?confirm=true`` as a small barrier against
> accidental destructive curl-from-history mistakes.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status

from ....web.schemas import CacheStatsDTO
from ....web.service import EnrichmentService
from ..deps import get_enrichment_service
from ..security.user_auth import (
    require_admin_api_key_or_admin_user,
    require_api_key_or_user,
)

router = APIRouter(tags=["cache"])


@router.get(
    "/cache",
    response_model=CacheStatsDTO,
    summary="Cache statistics (no IOC values exposed)",
    dependencies=[Depends(require_api_key_or_user)],
)
def cache_stats(
    service: EnrichmentService = Depends(get_enrichment_service),
) -> CacheStatsDTO:
    return service.get_cache_stats()


@router.delete(
    "/cache",
    status_code=status.HTTP_200_OK,
    summary="Clear the enrichment cache (admin operation — requires confirm=true)",
    dependencies=[Depends(require_admin_api_key_or_admin_user)],
)
def clear_cache(
    confirm: bool = Query(default=False, description="Must be true to proceed."),
    service: EnrichmentService = Depends(get_enrichment_service),
) -> dict:
    if not confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="clear_cache requires ?confirm=true",
        )
    result = service.clear_cache()
    return {
        "cleared": bool(result.get("cleared")),
        "removed_entries": int(result.get("removed_entries", 0)),
        "message": "Cache cleared." if result.get("cleared") else "Cache clear failed.",
    }
