"""``GET /reports/{report_id}``."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Path, status

from ....web.report_store import ReportStoreError
from ....web.service import EnrichmentService, ValidationError as AdapterValidationError
from ..deps import get_enrichment_service
from ..security.user_auth import require_api_key_or_user

router = APIRouter(
    tags=["reports"], dependencies=[Depends(require_api_key_or_user)]
)

# UUID4 pattern; routes that don't match this never reach the handler at all,
# which gives us a first-line defence against path-traversal attempts.
_UUID_PATTERN = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"


@router.get(
    "/reports/{report_id}",
    summary="Fetch a previously persisted report by id",
)
def get_report(
    report_id: str = Path(..., pattern=_UUID_PATTERN),
    service: EnrichmentService = Depends(get_enrichment_service),
) -> dict:
    try:
        report = service.get_report(report_id)
    except AdapterValidationError as exc:
        # Belt-and-braces — the path regex already filters bad ids, but if
        # the report-store layer raises for any reason we surface a 422.
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ReportStoreError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    if report is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Report not found"
        )
    return report
