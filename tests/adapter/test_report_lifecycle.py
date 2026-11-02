"""
Web report content, read-back validation and retention.

A persisted report holds the same allow-listed view the API returns, never
the raw provider data; reading one back passes the response schema and the
allow-lists again, and reports from before this policy are not served.
Retention removes expired or over-quota reports, only from the report
directory and only report-named files. Fake data and temporary directories only.
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ioc_enricher.models.ioc import IOCType
from ioc_enricher.models.result import (
    EnrichmentResult, ProviderResult, ProviderStatus, RiskLevel, RiskScore, ScoreBreakdown,
)
from ioc_enricher.web import report_store as store_module
from ioc_enricher.web.mappers import to_enrichment_dto
from ioc_enricher.web.report_store import ReportStore, ReportStoreError
from ioc_enricher.web.schemas import EnrichRequest
from ioc_enricher.web.service import EnrichmentService

_IOC = "203.0.113.7"
# Provider free text, and a provider error carrying a key-shaped value (real
# keys are 32+ characters; the API's error sanitiser masks values of 16+).
_RAW = ["PRIVATE-COMMENT-TEXT", "BANNER-SECRET", "SECRET123", "SECRET1234567890ABCD"]
_UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def _result(ioc: str = _IOC) -> EnrichmentResult:
    return EnrichmentResult(
        ioc=ioc,
        ioc_type=IOCType.IPV4,
        provider_results={
            "AbuseIPDB": ProviderResult("AbuseIPDB", ProviderStatus.SUCCESS, data={
                "abuse_confidence_score": 87, "total_reports": 3,
                "isp": "Example ISP ```break``` out",
                "recent_reports": [{"comment": "PRIVATE-COMMENT-TEXT from a reporter"}],
            }),
            "Shodan": ProviderResult("Shodan", ProviderStatus.SUCCESS, data={
                "ports": [22],
                "services": [{"port": 22, "banner": "BANNER-SECRET api_key=SECRET123"}],
            }),
            "GreyNoise": ProviderResult("GreyNoise", ProviderStatus.ERROR,
                                        error="Network error: api_key=SECRET1234567890ABCD"),
        },
        risk_score=RiskScore(score=21, level=RiskLevel.MEDIUM,
                             breakdown=ScoreBreakdown(abuseipdb=21),
                             reasons=["AbuseIPDB: 87% abuse confidence"],
                             active_data_points=[], detection_confidence=0.5),
        execution_time=0.4,
        timestamp=datetime(2026, 10, 27, 12, 0, tzinfo=timezone.utc),
    )


class _Enricher:
    def enrich(self, raw_ioc, save_report=None, use_cache=True):
        return _result(raw_ioc)


class _Clock:
    def __init__(self, now: float = 1_800_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def _service(tmp_path: Path) -> EnrichmentService:
    return EnrichmentService(enricher=_Enricher(), report_store=ReportStore(base_dir=tmp_path))


def _save(service: EnrichmentService, fmt: str) -> str:
    dto = service.enrich_single(EnrichRequest(ioc=_IOC, save_report_format=fmt))
    assert dto.report_id
    return dto.report_id


# ---------------------------------------------------------------------------
# What a report holds
# ---------------------------------------------------------------------------

class TestReportContent:

    def test_json_report_holds_the_allow_listed_view(self, tmp_path):
        rid = _save(_service(tmp_path), "json")
        stored = (tmp_path / f"{rid}.json").read_text(encoding="utf-8")
        for raw in _RAW:
            assert raw not in stored
        content = json.loads(stored)["content"]
        assert content["ioc"] == _IOC
        assert {p["name"] for p in content["providers"]} == {"AbuseIPDB", "Shodan", "GreyNoise"}

    def test_markdown_report_holds_no_raw_provider_text(self, tmp_path):
        rid = _save(_service(tmp_path), "markdown")
        stored = (tmp_path / f"{rid}.md").read_text(encoding="utf-8")
        for raw in _RAW:
            assert raw not in stored
        assert stored.count("```") % 2 == 0
        assert "```break```" not in stored

    def test_read_back_passes_the_schema(self, tmp_path):
        service = _service(tmp_path)
        rid = _save(service, "json")
        report = service.get_report(rid)
        assert set(report) == {"report_id", "format", "created_at", "metadata", "content"}
        assert report["content"]["ioc"] == _IOC
        assert set(report["metadata"]) <= {"request_id", "ioc_type"}

    def test_created_at_is_utc(self, tmp_path):
        service = _service(tmp_path)
        report = service.get_report(_save(service, "markdown"))
        created = datetime.fromisoformat(report["created_at"])
        assert created.utcoffset().total_seconds() == 0


class TestReadBackValidation:

    def _write(self, tmp_path: Path, payload: dict) -> str:
        rid = str(uuid.uuid4())
        payload = dict(payload, report_id=rid)
        (tmp_path / f"{rid}.json").write_text(json.dumps(payload), encoding="utf-8")
        return rid

    def _envelope(self, content, **extra) -> dict:
        payload = {"format": "json", "created_at": datetime.now(timezone.utc).isoformat(),
                   "metadata": {"request_id": "r1", "ioc_type": "ipv4"}, "content": content,
                   "schema": store_module.REPORT_SCHEMA_VERSION}
        payload.update(extra)
        return payload

    def test_report_from_before_the_policy_is_not_served(self, tmp_path):
        legacy = {"format": "json", "created_at": "2026-01-01T00:00:00+00:00", "metadata": {},
                  "content": _result().to_dict()}
        rid = self._write(tmp_path, legacy)
        assert _service(tmp_path).get_report(rid) is None

    def test_legacy_markdown_report_is_not_served(self, tmp_path):
        rid = str(uuid.uuid4())
        (tmp_path / f"{rid}.md").write_text("# old\nPRIVATE-COMMENT-TEXT", encoding="utf-8")
        assert _service(tmp_path).get_report(rid) is None

    def test_content_outside_the_schema_is_not_served(self, tmp_path):
        content = to_enrichment_dto(_result()).model_dump(mode="json")
        content["threat_intelligence"] = {"raw": "PRIVATE-COMMENT-TEXT"}
        rid = self._write(tmp_path, self._envelope(content))
        assert _service(tmp_path).get_report(rid) is None

    def test_tampered_fields_inside_the_schema_are_filtered(self, tmp_path):
        content = to_enrichment_dto(_result()).model_dump(mode="json")
        content["providers"][0]["data_summary"]["recent_reports"] = ["PRIVATE-COMMENT-TEXT"]
        content["meta"]["note"] = "PRIVATE-COMMENT-TEXT"
        rid = self._write(tmp_path, self._envelope(
            content, metadata={"request_id": "r1", "ioc_type": "ipv4", "ioc": _IOC}))
        report = _service(tmp_path).get_report(rid)
        assert "PRIVATE-COMMENT-TEXT" not in json.dumps(report)
        assert "ioc" not in report["metadata"]

    def test_unparseable_content_is_not_served(self, tmp_path):
        rid = self._write(tmp_path, self._envelope({"hello": "world"}))
        assert _service(tmp_path).get_report(rid) is None


# ---------------------------------------------------------------------------
# Retention
# ---------------------------------------------------------------------------

def _age(path: Path, seconds: float) -> None:
    stamp = time.time() - seconds
    os.utime(path, (stamp, stamp))


_DAY = 86_400


class TestRetention:

    def test_expired_reports_are_pruned(self, tmp_path):
        store = ReportStore(base_dir=tmp_path, retention_days=30)
        old_json = store.save_report({"a": 1}, "json")
        old_md = store.save_report("# old", "markdown")
        new_json = store.save_report({"b": 2}, "json")
        for path in tmp_path.iterdir():
            if path.name.startswith((old_json, old_md)):
                _age(path, 31 * _DAY)
        removed = store.prune()
        assert removed["expired"] == 2
        names = sorted(p.name for p in tmp_path.iterdir())
        assert names == [f"{new_json}.json"]

    def test_prune_only_touches_report_files(self, tmp_path):
        store = ReportStore(base_dir=tmp_path, retention_days=1)
        foreign = [tmp_path / "notes.json", tmp_path / "readme.md",
                   tmp_path / f"{uuid.uuid4()}.txt", tmp_path / f"{str(uuid.uuid4()).upper()}.json"]
        for path in foreign:
            path.write_text("keep", encoding="utf-8")
        nested = tmp_path / "sub"
        nested.mkdir()
        (nested / f"{uuid.uuid4()}.json").write_text("keep", encoding="utf-8")
        for path in tmp_path.rglob("*"):
            if path.is_file():
                _age(path, 10 * _DAY)
        store.prune()
        assert all(path.exists() for path in foreign)
        assert len(list(nested.iterdir())) == 1

    def test_size_cap_removes_the_oldest_reports_first(self, tmp_path):
        store = ReportStore(base_dir=tmp_path, retention_days=30, max_total_mb=1)
        ids = []
        for i in range(6):
            ids.append(store.save_report({"blob": "x" * 300_000}, "json"))
            _age(tmp_path / f"{ids[-1]}.json", 100 - i)
        store.prune()
        total = sum(p.stat().st_size for p in tmp_path.iterdir())
        assert total <= 1024 * 1024
        assert (tmp_path / f"{ids[-1]}.json").exists()
        assert not (tmp_path / f"{ids[0]}.json").exists()

    def test_prune_runs_from_save_at_most_once_per_interval(self, tmp_path, monkeypatch):
        clock = _Clock()
        store = ReportStore(base_dir=tmp_path, clock=clock)
        calls = []
        monkeypatch.setattr(store, "prune", lambda: calls.append(clock.now) or {})
        for _ in range(4):
            store.save_report({"a": 1}, "json")
        assert len(calls) == 1
        clock.now += store_module.PRUNE_INTERVAL_SECONDS
        store.save_report({"a": 1}, "json")
        assert len(calls) == 2

    def test_reports_vanishing_mid_prune_do_not_break_it(self, tmp_path, monkeypatch):
        store = ReportStore(base_dir=tmp_path, retention_days=1)
        rid = store.save_report({"a": 1}, "json")
        _age(tmp_path / f"{rid}.json", 5 * _DAY)
        listed = store._report_files()
        phantom = tmp_path / f"{uuid.uuid4()}.json"
        monkeypatch.setattr(store, "_report_files", lambda: [phantom] + listed)
        assert store.prune()["expired"] == 1

    def test_retention_settings_are_bounded(self, tmp_path):
        from ioc_enricher.utils.config import Config
        assert (Config.REPORT_RETENTION_DAYS, Config.REPORT_MAX_TOTAL_MB) == (30, 200)
        assert ReportStore(base_dir=tmp_path, retention_days=0).retention_days == 1
        assert ReportStore(base_dir=tmp_path, retention_days=10**9).retention_days == 3650
        assert ReportStore(base_dir=tmp_path, max_total_mb=0).max_total_mb == 1


class TestStoreWrites:

    def test_writes_are_atomic(self, tmp_path, monkeypatch):
        replaced = []
        real_replace = os.replace
        monkeypatch.setattr(store_module.os, "replace",
                            lambda src, dst: replaced.append(Path(dst).name) or real_replace(src, dst))
        store = ReportStore(base_dir=tmp_path)
        rid = store.save_report("# md", "markdown")
        assert sorted(replaced) == sorted([f"{rid}.md", f"{rid}.md.meta.json"])
        assert sorted(p.name for p in tmp_path.iterdir()) == sorted(replaced)

    def test_failure_log_has_no_report_id_or_exception_text(self, tmp_path, monkeypatch, caplog):
        def broken(src, dst):
            raise OSError(f"disk full writing {dst}")

        monkeypatch.setattr(store_module.os, "replace", broken)
        store = ReportStore(base_dir=tmp_path)
        with caplog.at_level(logging.DEBUG, logger="ioc_enricher"):
            with pytest.raises(ReportStoreError):
                store.save_report({"a": 1}, "json")
        assert not _UUID_RE.search(caplog.text)
        assert "disk full" not in caplog.text and str(tmp_path) not in caplog.text
        assert list(tmp_path.iterdir()) == []        # no temp file left behind

    @pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
    def test_report_files_are_private(self, tmp_path):
        base = tmp_path / "web"
        store = ReportStore(base_dir=base)
        rid = store.save_report({"a": 1}, "json")
        assert base.stat().st_mode & 0o777 == 0o700
        assert (base / f"{rid}.json").stat().st_mode & 0o777 == 0o600
