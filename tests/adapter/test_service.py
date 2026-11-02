"""
Unit tests for :class:`ioc_enricher.web.service.EnrichmentService`.

These tests never touch the network: a ``FakeEnricher`` stands in for the
real :class:`IOCEnricher`. We test:

* Schema-level validation rejects bad input early.
* Single-IOC enrichment produces a sanitised DTO.
* Batch enrichment de-duplicates and reports partial failures.
* ``get_provider_status`` exposes no secrets.
* ``get_cache_stats`` exposes no IOC values.
* Errors raised by the engine are sanitised before being returned.
* ``save_report_format`` results in a UUID report id (not an IOC-derived one).
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from ioc_enricher.models.ioc import IOCType
from ioc_enricher.models.result import (
    EnrichmentResult,
    ProviderResult,
    ProviderStatus,
    RiskLevel,
    RiskScore,
    ScoreBreakdown,
)
from ioc_enricher.web.report_store import ReportStore
from ioc_enricher.web.schemas import BatchEnrichRequest, EnrichRequest
from ioc_enricher.web.service import (
    EnrichmentExecutionError,
    EnrichmentService,
    ValidationError,
)

_SECRET_SHAPED_VALUE = "s" + "k-" + "LEAKED1234567890abcdef"


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------

class _FakeCache:
    def __init__(self) -> None:
        self.cleared = 0

    def stats(self) -> Dict[str, Any]:
        return {
            "entry_count": 3,
            "total_size_kb": 12.5,
            "ttl_hours": 24.0,
            "enabled": True,
        }

    def clear(self) -> int:
        self.cleared += 1
        return 3


class _FakeAI:
    enabled = False


class FakeEnricher:
    """Stands in for IOCEnricher, never makes a network call."""

    def __init__(
        self,
        result_factory=None,
        provider_status: Optional[Dict[str, bool]] = None,
        raise_on: Optional[Dict[str, Exception]] = None,
    ) -> None:
        self._result_factory = result_factory or _default_result
        self._provider_status = provider_status or {"VirusTotal": True}
        self._raise_on = raise_on or {}
        self._cache = _FakeCache()
        self._ai = _FakeAI()
        self.calls: List[str] = []

    def enrich(
        self,
        raw_ioc: str,
        save_report: Optional[str] = None,
        use_cache: bool = True,
    ) -> EnrichmentResult:
        self.calls.append(raw_ioc)
        if raw_ioc in self._raise_on:
            raise self._raise_on[raw_ioc]
        return self._result_factory(raw_ioc)

    def provider_status(self) -> Dict[str, bool]:
        return dict(self._provider_status)


def _default_result(ioc: str) -> EnrichmentResult:
    return EnrichmentResult(
        ioc=ioc,
        ioc_type=IOCType.IPV4,
        provider_results={
            "VirusTotal": ProviderResult(
                provider="VirusTotal",
                status=ProviderStatus.SUCCESS,
                data={
                    "malicious": 1,
                    "total_scans": 70,
                    "raw_xml": "<x/>",
                    "api_key": "dummy-provider-token-redaction-check",
                },
                response_time=0.1,
                timestamp=datetime(2026, 1, 1),
            ),
        },
        risk_score=RiskScore(
            score=10,
            level=RiskLevel.LOW,
            breakdown=ScoreBreakdown(virustotal=10),
            reasons=["one vendor flagged"],
            active_data_points=[],
            detection_confidence=0.5,
        ),
        execution_time=0.5,
        timestamp=datetime(2026, 1, 1),
        from_cache=False,
    )


# ---------------------------------------------------------------------------
# Schema-level validation
# ---------------------------------------------------------------------------

class TestSchemaValidation:
    def test_empty_ioc_rejected(self) -> None:
        from pydantic import ValidationError as PydValidationError
        with pytest.raises(PydValidationError):
            EnrichRequest(ioc="   ")

    def test_overlong_ioc_rejected(self) -> None:
        from pydantic import ValidationError as PydValidationError
        with pytest.raises(PydValidationError):
            EnrichRequest(ioc="a" * 2049)

    def test_unknown_ioc_type_rejected(self) -> None:
        from pydantic import ValidationError as PydValidationError
        with pytest.raises(PydValidationError):
            EnrichRequest(ioc="8.8.8.8", ioc_type="ipv5")

    def test_unknown_report_format_rejected(self) -> None:
        from pydantic import ValidationError as PydValidationError
        with pytest.raises(PydValidationError):
            EnrichRequest(ioc="8.8.8.8", save_report_format="pdf")

    def test_batch_size_cap(self) -> None:
        from pydantic import ValidationError as PydValidationError
        with pytest.raises(PydValidationError):
            BatchEnrichRequest(iocs=[f"1.1.1.{i}" for i in range(0, 51)])

    def test_batch_strips_and_drops_empties(self) -> None:
        req = BatchEnrichRequest(iocs=["  1.1.1.1  ", "   ", "8.8.8.8"])
        assert req.iocs == ["1.1.1.1", "8.8.8.8"]


# ---------------------------------------------------------------------------
# enrich_single
# ---------------------------------------------------------------------------

class TestEnrichSingle:
    def test_happy_path(self, tmp_path: Path) -> None:
        svc = EnrichmentService(
            enricher=FakeEnricher(),
            report_store=ReportStore(base_dir=tmp_path),
        )
        dto = svc.enrich_single(EnrichRequest(ioc="8.8.8.8"))
        assert dto.ioc == "8.8.8.8"
        assert dto.ioc_type == "ipv4"
        assert dto.risk.level == "LOW"
        assert dto.meta.get("request_id")
        # provider summary must be whitelisted — raw_xml/api_key dropped
        assert "raw_xml" not in dto.providers[0].data_summary
        assert "api_key" not in dto.providers[0].data_summary

    def test_validation_error_from_engine_is_wrapped(self, tmp_path: Path) -> None:
        fake = FakeEnricher(raise_on={"bad-ioc": ValueError("Invalid IOC.")})
        svc = EnrichmentService(
            enricher=fake, report_store=ReportStore(base_dir=tmp_path)
        )
        with pytest.raises(ValidationError):
            svc.enrich_single(EnrichRequest(ioc="bad-ioc"))

    def test_execution_error_is_sanitised(self, tmp_path: Path) -> None:
        fake = FakeEnricher(
            raise_on={"8.8.8.8": RuntimeError(
                f"boom api_key={_SECRET_SHAPED_VALUE} leaked"
            )}
        )
        svc = EnrichmentService(
            enricher=fake, report_store=ReportStore(base_dir=tmp_path)
        )
        with pytest.raises(EnrichmentExecutionError) as exc_info:
            svc.enrich_single(EnrichRequest(ioc="8.8.8.8"))
        assert _SECRET_SHAPED_VALUE not in str(exc_info.value)

    def test_ioc_type_mismatch_rejected(self, tmp_path: Path) -> None:
        svc = EnrichmentService(
            enricher=FakeEnricher(),  # returns ipv4
            report_store=ReportStore(base_dir=tmp_path),
        )
        with pytest.raises(ValidationError):
            svc.enrich_single(EnrichRequest(ioc="8.8.8.8", ioc_type="domain"))

    def test_save_report_produces_uuid_report_id(self, tmp_path: Path) -> None:
        store = ReportStore(base_dir=tmp_path)
        svc = EnrichmentService(enricher=FakeEnricher(), report_store=store)
        dto = svc.enrich_single(
            EnrichRequest(ioc="8.8.8.8", save_report_format="json")
        )
        assert dto.report_id is not None
        assert len(dto.report_id) == 36
        # And the report is retrievable through the service.
        fetched = svc.get_report(dto.report_id)
        assert fetched is not None
        assert fetched["format"] == "json"


# ---------------------------------------------------------------------------
# enrich_batch
# ---------------------------------------------------------------------------

class TestEnrichBatch:
    def test_dedup_and_summary(self, tmp_path: Path) -> None:
        svc = EnrichmentService(
            enricher=FakeEnricher(),
            report_store=ReportStore(base_dir=tmp_path),
        )
        resp = svc.enrich_batch(
            BatchEnrichRequest(iocs=["1.1.1.1", "1.1.1.1", "8.8.8.8"])
        )
        assert len(resp.results) == 2
        assert resp.summary["total"] == 3
        assert resp.summary["unique"] == 2
        assert resp.summary["success"] == 2
        assert resp.summary["failed"] == 0
        assert resp.summary["duplicates_removed"] == 1

    def test_partial_failure_does_not_break_batch(self, tmp_path: Path) -> None:
        fake = FakeEnricher(raise_on={"bad": ValueError("Invalid IOC.")})
        svc = EnrichmentService(
            enricher=fake, report_store=ReportStore(base_dir=tmp_path)
        )
        resp = svc.enrich_batch(BatchEnrichRequest(iocs=["1.1.1.1", "bad", "8.8.8.8"]))
        assert resp.summary["success"] == 2
        assert resp.summary["failed"] == 1
        assert resp.errors[0]["ioc"] == "bad"
        assert resp.errors[0]["error_type"] == "validation_error"

    def test_execution_error_in_batch_sanitised(self, tmp_path: Path) -> None:
        fake = FakeEnricher(
            raise_on={"x": RuntimeError(
                f'File "/opt/app/foo.py", line 42, in bar\n{_SECRET_SHAPED_VALUE}'
            )}
        )
        svc = EnrichmentService(
            enricher=fake, report_store=ReportStore(base_dir=tmp_path)
        )
        resp = svc.enrich_batch(BatchEnrichRequest(iocs=["x", "1.1.1.1"]))
        assert resp.summary["failed"] == 1
        msg = resp.errors[0]["message"]
        assert "/opt/app/foo.py" not in msg
        assert _SECRET_SHAPED_VALUE not in msg


# ---------------------------------------------------------------------------
# Provider status + cache stats
# ---------------------------------------------------------------------------

class TestProviderStatus:
    def test_no_secrets_in_response(self, tmp_path: Path) -> None:
        svc = EnrichmentService(
            enricher=FakeEnricher(provider_status={"VirusTotal": True}),
            report_store=ReportStore(base_dir=tmp_path),
        )
        resp = svc.get_provider_status()
        # Status DTOs must not contain anything that even looks like a key.
        for prov in resp.providers:
            payload = prov.model_dump()
            for v in payload.values():
                if v is None:
                    continue
                s = str(v)
                assert "sk-" not in s
                assert "AKIA" not in s
                assert "api_key" not in s.lower() or s.lower() == "api_key"


class TestCacheStats:
    def test_returns_counts_only(self, tmp_path: Path) -> None:
        svc = EnrichmentService(
            enricher=FakeEnricher(),
            report_store=ReportStore(base_dir=tmp_path),
        )
        stats = svc.get_cache_stats()
        assert stats.entries == 3
        assert stats.ttl_hours == 24.0
        # We never expose IOC values from cache stats — model has no such field.
        assert "ioc" not in stats.model_dump()
        assert "iocs" not in stats.model_dump()


class TestClearCache:
    def test_clears_and_reports_count(self, tmp_path: Path) -> None:
        fake = FakeEnricher()
        svc = EnrichmentService(
            enricher=fake, report_store=ReportStore(base_dir=tmp_path)
        )
        out = svc.clear_cache()
        assert out["cleared"] is True
        assert out["removed_entries"] == 3
        assert fake._cache.cleared == 1
