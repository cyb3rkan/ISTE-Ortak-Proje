"""
Shared pytest configuration for the top-level ``tests/`` tree.

* Exposes :class:`FakeService` — an :class:`EnrichmentService`-shaped stub
  used by the API and security tests so we never touch the real provider
  network at test time.

``sys.path`` shim
-----------------
The recommended way to run the suite is after ``pip install -e .`` from the
repository root, which makes the ``ioc_enricher`` package importable through
the normal mechanism. The small fallback below keeps a *fresh* checkout
runnable for contributors who have not yet installed the package; once the
editable install is in place it is a harmless no-op (the path is already
resolvable, so the ``insert`` short-circuits). See ``README.md`` →
"Running the tests" for details.
"""
from __future__ import annotations

import importlib.util
import os
import sys

# Hermetic tests: never load a developer's real .env (provider / AI keys),
# and keep the app log on the console (captured by pytest) — the default
# LOG_FILE is logs/ioc_enricher.log under the working directory, i.e. the
# real runtime log. Must run before anything below imports
# ioc_enricher.utils.config.
os.environ["IOC_ENRICHER_DOTENV"] = "0"
os.environ["LOG_FILE"] = ""
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

_REPO_ROOT = Path(__file__).resolve().parent.parent
_CANONICAL_PKG_ROOT = _REPO_ROOT / "ioc_enricher"

# Only patch sys.path when the package cannot already be imported — i.e. the
# project has not been `pip install -e`'d. This keeps installed environments
# pristine while still supporting fresh checkouts. A spec without an origin is
# a namespace package: the outer ioc_enricher/ directory, found through the
# current directory that `python -m pytest` puts on sys.path — not the package.
_spec = importlib.util.find_spec("ioc_enricher")
if _spec is None or _spec.origin is None:
    if str(_CANONICAL_PKG_ROOT) not in sys.path:
        sys.path.insert(0, str(_CANONICAL_PKG_ROOT))
del _spec


# ---------------------------------------------------------------------------
# Shared service test double
# ---------------------------------------------------------------------------

from ioc_enricher.web.schemas import (  # noqa: E402  (after sys.path tweak)
    BatchEnrichRequest,
    BatchEnrichResponse,
    CacheStatsDTO,
    EnrichmentDTO,
    EnrichRequest,
    ProviderStatusDTO,
    ProviderStatusResponse,
    RiskDTO,
)


class FakeService:
    """Minimal stand-in for :class:`EnrichmentService` used by API tests."""

    def __init__(self) -> None:
        self.enrich_calls: List[EnrichRequest] = []
        self.batch_calls: List[BatchEnrichRequest] = []
        self.clear_cache_calls: int = 0
        self._reports: Dict[str, Dict[str, Any]] = {}
        self._raise_validation_for: Optional[str] = None
        self._raise_execution_for: Optional[str] = None
        self._provider_status: ProviderStatusResponse = ProviderStatusResponse(
            providers=[
                ProviderStatusDTO(
                    name="VirusTotal", enabled=False, configured=False,
                    status="disabled", last_error=None,
                ),
            ],
            ai_enabled=False,
        )
        self._cache_stats: CacheStatsDTO = CacheStatsDTO(
            entries=3, size_bytes=12800, ttl_hours=24.0
        )

    # --- helpers used by tests ----------------------------------------

    def add_report(self, report_id: str, payload: Dict[str, Any]) -> None:
        self._reports[report_id] = payload

    def raise_validation_for(self, ioc: str) -> None:
        self._raise_validation_for = ioc

    def raise_execution_for(self, ioc: str) -> None:
        self._raise_execution_for = ioc

    def set_ai_enabled(self, enabled: bool) -> None:
        """Toggle the ``ai_enabled`` flag the /health endpoint reports."""
        self._provider_status = ProviderStatusResponse(
            providers=list(self._provider_status.providers),
            ai_enabled=enabled,
        )

    # --- the surface FastAPI calls into --------------------------------

    def enrich_single(self, request: EnrichRequest) -> EnrichmentDTO:
        # Imported here so the import order survives sys.path edits.
        from ioc_enricher.web.service import (
            EnrichmentExecutionError,
            ValidationError as AdapterValidationError,
        )
        self.enrich_calls.append(request)
        if request.ioc == self._raise_validation_for:
            raise AdapterValidationError("Invalid IOC.")
        if request.ioc == self._raise_execution_for:
            raise EnrichmentExecutionError("Enrichment pipeline failure.")

        return EnrichmentDTO(
            ioc=request.ioc,
            ioc_type="ipv4",
            risk=RiskDTO(
                score=10,
                level="LOW",
                reasons=["fake"],
                detection_confidence=0.5,
                active_data_points=None,
            ),
            providers=[],
            mitre=[],
            ai_analysis=None,
            meta={
                "from_cache": False,
                "execution_time_ms": 1.0,
                "timestamp": datetime(2026, 1, 1).isoformat(),
                "request_id": "fake-req-id",
            },
            report_id=None,
        )

    def enrich_batch(self, request: BatchEnrichRequest) -> BatchEnrichResponse:
        from ioc_enricher.web.service import (
            EnrichmentExecutionError,
            ValidationError as AdapterValidationError,
        )
        self.batch_calls.append(request)
        results: List[EnrichmentDTO] = []
        errors: List[Dict[str, Any]] = []
        seen: set[str] = set()
        unique: List[str] = []
        for v in request.iocs:
            if v not in seen:
                seen.add(v)
                unique.append(v)
        for v in unique:
            try:
                results.append(
                    self.enrich_single(
                        EnrichRequest(
                            ioc=v,
                            ioc_type=request.ioc_type,
                            use_cache=request.use_cache,
                            save_report_format=request.save_report_format,
                        )
                    )
                )
            except AdapterValidationError as exc:
                errors.append({"ioc": v, "error_type": "validation_error",
                               "message": str(exc)})
            except EnrichmentExecutionError as exc:
                errors.append({"ioc": v, "error_type": "execution_error",
                               "message": str(exc)})

        return BatchEnrichResponse(
            results=results,
            errors=errors,
            summary={
                "total": len(request.iocs),
                "unique": len(unique),
                "success": len(results),
                "failed": len(errors),
                "duplicates_removed": len(request.iocs) - len(unique),
            },
        )

    def get_provider_status(self) -> ProviderStatusResponse:
        return self._provider_status

    def get_cache_stats(self) -> CacheStatsDTO:
        return self._cache_stats

    def clear_cache(self) -> Dict[str, Any]:
        self.clear_cache_calls += 1
        return {"cleared": True, "removed_entries": 3}

    def get_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        return self._reports.get(report_id)
