"""
Unit tests for :class:`ioc_enricher.web.report_store.ReportStore`.

Key invariants under test:

* Reports are UUID-keyed and round-trip through ``save_report`` / ``get_report``.
* Bogus report ids (including path traversal attempts) are rejected.
* Unknown formats are rejected.
* Files always land *inside* the configured base directory.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from ioc_enricher.web.report_store import ReportStore, ReportStoreError


@pytest.fixture()
def store(tmp_path: Path) -> ReportStore:
    return ReportStore(base_dir=tmp_path / "reports")


class TestSaveAndGet:
    def test_json_round_trip(self, store: ReportStore) -> None:
        rid = store.save_report(
            content={"hello": "world"}, format="json", metadata={"k": "v"}
        )
        assert isinstance(rid, str) and len(rid) == 36
        out = store.get_report(rid)
        assert out is not None
        assert out["report_id"] == rid
        assert out["format"] == "json"
        assert out["content"]["hello"] == "world"
        assert out["metadata"]["k"] == "v"

    def test_markdown_round_trip(self, store: ReportStore) -> None:
        rid = store.save_report(
            content="# Title\nBody", format="markdown", metadata={"ioc": "8.8.8.8"}
        )
        out = store.get_report(rid)
        assert out is not None
        assert out["format"] == "markdown"
        assert out["content"].startswith("# Title")
        assert out["metadata"]["ioc"] == "8.8.8.8"

    def test_files_land_inside_base_dir(self, store: ReportStore, tmp_path: Path) -> None:
        rid = store.save_report(content={"x": 1}, format="json", metadata={})
        produced = list(store.base_dir.glob("*.json"))
        assert any(p.name == f"{rid}.json" for p in produced)
        # The base dir itself must be the tmp dir we asked for.
        assert store.base_dir == (tmp_path / "reports").resolve()

    def test_missing_report_returns_none(self, store: ReportStore) -> None:
        missing = "00000000-0000-4000-8000-000000000000"
        assert store.get_report(missing) is None


class TestDelete:
    def test_delete_round_trip(self, store: ReportStore) -> None:
        rid = store.save_report(content={"a": 1}, format="json", metadata={})
        assert store.get_report(rid) is not None
        assert store.delete_report(rid) is True
        assert store.get_report(rid) is None

    def test_delete_unknown_is_false(self, store: ReportStore) -> None:
        rid = "00000000-0000-4000-8000-000000000000"
        assert store.delete_report(rid) is False


class TestPathTraversal:
    @pytest.mark.parametrize(
        "bad_id",
        [
            "../etc/passwd",
            "..\\..\\windows\\system32\\config\\sam",
            "/etc/passwd",
            "C:\\Users\\victim\\.env",
            "report.json",
            "../../report",
            "00000000-0000-4000-8000-00000000000",   # 35 chars
            "ZZZZZZZZ-0000-4000-8000-000000000000",  # not hex
            "",
            None,
        ],
    )
    def test_reject_malicious_report_ids_on_get(
        self, store: ReportStore, bad_id
    ) -> None:
        with pytest.raises(ReportStoreError):
            store.get_report(bad_id)  # type: ignore[arg-type]

    @pytest.mark.parametrize("bad_id", ["../escape", "not-a-uuid"])
    def test_reject_malicious_report_ids_on_delete(
        self, store: ReportStore, bad_id: str
    ) -> None:
        with pytest.raises(ReportStoreError):
            store.delete_report(bad_id)


class TestFormatValidation:
    def test_unknown_format_rejected(self, store: ReportStore) -> None:
        with pytest.raises(ReportStoreError):
            store.save_report(content={"x": 1}, format="yaml", metadata={})

    def test_markdown_requires_string_content(self, store: ReportStore) -> None:
        with pytest.raises(ReportStoreError):
            store.save_report(content={"x": 1}, format="markdown", metadata={})  # type: ignore[arg-type]
