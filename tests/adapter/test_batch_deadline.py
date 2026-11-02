"""
Regression tests: batch enrichment has an end-to-end time budget.

Before the fix a 50-IOC batch ran every item sequentially with no overall
bound, so slow / unreachable providers (connect + read timeouts, retries,
provider-quota sleeps) could pin a server worker for many minutes.

A fake, manually-advanced clock keeps these tests deterministic and fast.
"""
from __future__ import annotations

from pathlib import Path

from ioc_enricher.providers.base import BaseProvider
from ioc_enricher.web.report_store import ReportStore
from ioc_enricher.web.schemas import BatchEnrichRequest
from ioc_enricher.web.service import EnrichmentService

from .test_service import FakeEnricher


class _FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class _SlowEnricher(FakeEnricher):
    """Each enrich() 'takes' *seconds* on the fake clock."""

    def __init__(self, clock: _FakeClock, seconds: float) -> None:
        super().__init__()
        self._clock = clock
        self._seconds = seconds

    def enrich(self, raw_ioc, save_report=None, use_cache=True):
        self._clock.now += self._seconds
        return super().enrich(raw_ioc, save_report=save_report, use_cache=use_cache)


def _svc(tmp_path: Path, enricher, clock, deadline):
    return EnrichmentService(
        enricher=enricher,
        report_store=ReportStore(base_dir=tmp_path),
        batch_deadline_seconds=deadline,
        clock=clock,
    )


_IOCS = [f"10.0.0.{i}" for i in range(1, 11)]


class TestBatchDeadline:
    def test_stops_starting_new_items_after_deadline(self, tmp_path: Path) -> None:
        clock = _FakeClock()
        slow = _SlowEnricher(clock, seconds=30)
        resp = _svc(tmp_path, slow, clock, deadline=100).enrich_batch(
            BatchEnrichRequest(iocs=_IOCS)
        )
        # Items start at t=0,30,60,90 (<100) -> 4 processed; the rest skipped.
        assert len(slow.calls) == 4
        assert resp.summary["success"] == 4
        assert resp.summary["failed"] == 6
        assert resp.summary["deadline_exceeded"] == 6
        assert all(e["error_type"] == "deadline_exceeded" for e in resp.errors)

    def test_order_and_coverage_preserved(self, tmp_path: Path) -> None:
        clock = _FakeClock()
        slow = _SlowEnricher(clock, seconds=30)
        resp = _svc(tmp_path, slow, clock, deadline=100).enrich_batch(
            BatchEnrichRequest(iocs=_IOCS)
        )
        assert [r.ioc for r in resp.results] == _IOCS[:4]
        assert [e["ioc"] for e in resp.errors] == _IOCS[4:]
        # Every unique IOC is accounted for exactly once.
        assert resp.summary["success"] + resp.summary["failed"] == resp.summary["unique"]

    def test_fast_batch_unaffected(self, tmp_path: Path) -> None:
        clock = _FakeClock()
        fast = _SlowEnricher(clock, seconds=0.1)
        resp = _svc(tmp_path, fast, clock, deadline=100).enrich_batch(
            BatchEnrichRequest(iocs=_IOCS)
        )
        assert resp.summary["success"] == 10
        assert resp.summary["failed"] == 0
        assert resp.summary["deadline_exceeded"] == 0

    def test_deadline_disabled_processes_everything(self, tmp_path: Path) -> None:
        clock = _FakeClock()
        slow = _SlowEnricher(clock, seconds=1000)
        resp = _svc(tmp_path, slow, clock, deadline=None).enrich_batch(
            BatchEnrichRequest(iocs=_IOCS)
        )
        assert resp.summary["success"] == 10

    def test_first_item_always_attempted(self, tmp_path: Path) -> None:
        clock = _FakeClock()
        slow = _SlowEnricher(clock, seconds=500)
        resp = _svc(tmp_path, slow, clock, deadline=1).enrich_batch(
            BatchEnrichRequest(iocs=_IOCS[:3])
        )
        assert resp.summary["success"] == 1
        assert resp.summary["deadline_exceeded"] == 2

    def test_duplicates_not_reenriched(self, tmp_path: Path) -> None:
        clock = _FakeClock()
        slow = _SlowEnricher(clock, seconds=1)
        _svc(tmp_path, slow, clock, deadline=100).enrich_batch(
            BatchEnrichRequest(iocs=["1.1.1.1"] * 5 + ["8.8.8.8"])
        )
        assert slow.calls == ["1.1.1.1", "8.8.8.8"]

    def test_default_service_has_no_deadline(self, tmp_path: Path) -> None:
        # Backward compatible constructor: no deadline unless configured.
        clock = _FakeClock()
        slow = _SlowEnricher(clock, seconds=1000)
        svc = EnrichmentService(enricher=slow, report_store=ReportStore(base_dir=tmp_path))
        resp = svc.enrich_batch(BatchEnrichRequest(iocs=_IOCS[:3]))
        assert resp.summary["success"] == 3


class TestDeadlineWiring:
    def test_settings_default_and_env(self, monkeypatch) -> None:
        from ioc_enricher.web.settings import load_settings

        monkeypatch.delenv("IOC_WEB_BATCH_DEADLINE_SECONDS", raising=False)
        assert load_settings().batch_deadline_seconds == 120
        monkeypatch.setenv("IOC_WEB_BATCH_DEADLINE_SECONDS", "15")
        assert load_settings().batch_deadline_seconds == 15

    def test_default_service_uses_configured_deadline(self, monkeypatch) -> None:
        from ioc_enricher.web.api import deps

        monkeypatch.setenv("IOC_WEB_BATCH_DEADLINE_SECONDS", "7")
        monkeypatch.setattr(deps, "_default_enricher", lambda: FakeEnricher())
        deps._default_service.cache_clear()
        deps._default_settings.cache_clear()
        try:
            assert deps.get_enrichment_service()._batch_deadline_seconds == 7
        finally:
            deps._default_service.cache_clear()
            deps._default_settings.cache_clear()


class _Dummy(BaseProvider):
    @property
    def name(self) -> str:
        return "Dummy"

    def _get_headers(self):
        return {}


class TestProviderRetryBudget:
    def test_read_timeouts_are_not_retried(self) -> None:
        retry = _Dummy(api_key="k", timeout=5)._session.get_adapter("https://x").max_retries
        # A provider that already took the full read timeout is not retried:
        # that only multiplies worst-case latency per IOC.
        assert retry.read == 0
        assert retry.total <= 2

    def test_http_adapter_still_absent(self) -> None:
        session = _Dummy(api_key="k", timeout=5)._session
        assert "http://" not in session.adapters
