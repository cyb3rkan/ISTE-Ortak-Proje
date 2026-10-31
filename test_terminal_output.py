"""
Untrusted text in the CLI / report output, and saved report file names.

Provider answers (banners, ISP/org names, titles), AI text and URL IOCs can
carry terminal control sequences: ESC-based CSI/OSC (clear the screen, set
the window title, fake colours), 8-bit C1 controls, carriage returns and
bidi overrides that reorder what the analyst reads. Every human-readable
output shows them as visible escapes instead; JSON stays lossless. Saved
report names never contain the raw IOC and never overwrite an earlier file.
Only fake data, temporary directories and no network.
"""
from __future__ import annotations

import importlib
import io
import json
import re
import sys
from datetime import datetime, timezone

import pytest

from ioc_enricher.models.ioc import IOCType
from ioc_enricher.models.result import (
    AIAnalysis, EnrichmentResult, ProviderResult, ProviderStatus, Recommendation,
    RiskLevel, RiskScore, ScoreBreakdown,
)
from ioc_enricher.reports.generator import ReportGenerator
from ioc_enricher.utils.config import Config

ESC, BEL = chr(0x1B), chr(0x07)
C1_CSI = chr(0x9B)
RLO = chr(0x202E)
CR = chr(0x0D)

CLEAR_SCREEN = ESC + "[2J"
SET_TITLE = ESC + "]0;pwned" + BEL
FAKE_RED = ESC + "[1;31m"
INJECTED = (CLEAR_SCREEN, SET_TITLE, FAKE_RED, C1_CSI + "2J", RLO, CR)
URL_IOC = "http://evil.example/" + CLEAR_SCREEN + "x"


def _result(ioc: str = "203.0.113.7", ioc_type: IOCType = IOCType.IPV4) -> EnrichmentResult:
    hostile = f"isp{CLEAR_SCREEN}{SET_TITLE}{FAKE_RED}FAKE{C1_CSI}2J tail{CR}SCORE 0/100{RLO}exe.pdf"
    return EnrichmentResult(
        ioc=ioc, ioc_type=ioc_type,
        provider_results={
            "Shodan": ProviderResult("Shodan", ProviderStatus.SUCCESS,
                                     data={"isp": hostile, "asn": "AS64500"}, response_time=0.1),
            "GreyNoise": ProviderResult("GreyNoise", ProviderStatus.ERROR,
                                        error=f"HTTP 500 {CLEAR_SCREEN}", response_time=0.2),
        },
        risk_score=RiskScore(score=40, level=RiskLevel.MEDIUM, breakdown=ScoreBreakdown(shodan=40),
                             reasons=[f"reason {SET_TITLE}"], active_data_points=[],
                             detection_confidence=0.4),
        ai_analysis=AIAnalysis(
            summary=f"summary {CLEAR_SCREEN}", analyst_note=f"note {RLO}",
            why_malicious=[f"why {FAKE_RED}"],
            prioritized_recommendations=[Recommendation(action=f"block {SET_TITLE}", priority="high",
                                                        rationale=f"because {C1_CSI}2J")],
            ai_provider="groq"),
        timestamp=datetime(2026, 10, 28, tzinfo=timezone.utc))


def _assert_inert(text: str) -> None:
    for sequence in INJECTED:
        assert sequence not in text, repr(sequence)


class TestHumanReadableOutputs:

    def test_terminal_report_shows_control_sequences_as_visible_escapes(self):
        out = ReportGenerator().to_terminal(_result())
        _assert_inert(out)
        assert "\\x1b[2J" in out and "\\u202e" in out
        assert "isp" in out and "AS64500" in out          # ordinary text is unchanged
        assert ESC + "[0m" in out                         # the report's own colours still work

    def test_table_report_has_no_raw_control_characters(self):
        out = ReportGenerator().to_table(_result(URL_IOC, IOCType.URL))
        assert ESC not in out and C1_CSI not in out and RLO not in out

    def test_markdown_report_is_inert(self):
        _assert_inert(ReportGenerator().to_markdown(_result(URL_IOC, IOCType.URL)))

    @pytest.mark.parametrize("render", ["to_json", "to_ndjson"])
    def test_json_outputs_escape_controls_and_stay_lossless(self, render):
        result = _result(URL_IOC, IOCType.URL)
        out = getattr(ReportGenerator(), render)(result)
        _assert_inert(out)
        decoded = json.loads(out)
        assert decoded == json.loads(json.dumps(result.to_dict(), default=str))


# ---------------------------------------------------------------------------
# Saved report files
# ---------------------------------------------------------------------------

def _config_classes() -> list:
    classes = [Config]
    for name in ("ioc_enricher.utils.config", "ioc_enricher.cli.main",
                 "ioc_enricher.utils.cache", "ioc_enricher.reports.generator"):
        cls = getattr(importlib.import_module(name), "Config", None)
        if cls is not None and cls not in classes:
            classes.append(cls)
    return classes


@pytest.fixture
def reports_dir(tmp_path, monkeypatch):
    for cls in _config_classes():
        for attr, sub in (("REPORTS_DIR", "reports"), ("DATA_DIR", "data"),
                          ("CACHE_DIR", "data/cache"), ("LOGS_DIR", "logs")):
            monkeypatch.setattr(cls, attr, tmp_path / sub)
    return tmp_path / "reports"


_NAME = re.compile(r"ioc_(?P<type>[a-z0-9]+)_\d{8}T\d{6}Z_[0-9a-f]{8}\.(json|md|txt|ndjson)")


class TestSavedReportNames:

    @pytest.mark.parametrize("fmt", ["json", "markdown", "table", "ndjson"])
    def test_name_has_no_raw_ioc(self, reports_dir, fmt):
        path = ReportGenerator().save(_result("alice.wonder@corp.example", IOCType.EMAIL), fmt)
        assert path.parent == reports_dir
        match = _NAME.fullmatch(path.name)
        assert match and match["type"] == "email"
        for fragment in ("alice", "wonder", "corp"):
            assert fragment not in path.name

    def test_saving_twice_never_overwrites(self, reports_dir):
        gen = ReportGenerator()
        first = gen.save(_result(), "json")
        second = gen.save(_result(), "json")
        assert first != second
        assert first.exists() and second.exists()

    @pytest.mark.parametrize("stem", ["../escape", "a/b", "..", "", "x" * 200])
    def test_explicit_stem_cannot_leave_the_reports_dir(self, reports_dir, stem):
        with pytest.raises(ValueError):
            ReportGenerator().save(_result(), "json", stem=stem)
        assert not (reports_dir.parent / "escape.json").exists()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

class TestCli:

    def test_echoed_ioc_is_inert(self, reports_dir, capsys):
        from ioc_enricher.cli.main import main
        main(["--no-banner", "--no-cache", "--ioc", URL_IOC])
        captured = capsys.readouterr()
        _assert_inert(captured.out + captured.err)

    def test_invalid_file_entries_are_inert(self, reports_dir, tmp_path, capsys):
        from ioc_enricher.cli.main import main
        ioc_file = tmp_path / "iocs.txt"
        ioc_file.write_text(f"not-an-ioc{CLEAR_SCREEN}{RLO}\n203.0.113.7\n", encoding="utf-8")
        main(["--no-banner", "--no-cache", "--file", str(ioc_file)])
        _assert_inert(capsys.readouterr().out)

    @pytest.mark.parametrize("fmt, ext", [("json", "json"), ("table", "txt"), ("ndjson", "ndjson")])
    def test_save_writes_the_requested_format_and_prints_where(self, reports_dir, capsys, fmt, ext):
        from ioc_enricher.cli.main import main
        assert main(["--no-banner", "--no-cache", "--ioc", "203.0.113.7", "--save", fmt]) == 0
        [saved] = list(reports_dir.glob(f"*.{ext}"))
        assert "203.0.113.7" not in saved.name
        assert saved.name in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Evidence status in every human-readable format
# ---------------------------------------------------------------------------

def _evidence_result(status, coverage, unavailable=(), score=0, level=RiskLevel.LOW):
    return EnrichmentResult(
        ioc="203.0.113.7", ioc_type=IOCType.IPV4, provider_results={},
        risk_score=RiskScore(score=score, level=level, breakdown=ScoreBreakdown(),
                             evidence_status=status, provider_coverage=coverage,
                             unavailable_providers=list(unavailable)),
    )


_NO_EVIDENCE = dict(status="insufficient_data",
                    coverage={"queried": 0, "responded": 0, "failed": 0, "not_found": 0})
_PARTIAL = dict(status="partial", unavailable=["GreyNoise"], score=25, level=RiskLevel.MEDIUM,
                coverage={"queried": 2, "responded": 1, "failed": 1, "not_found": 0})
_COMPLETE = dict(status="complete", score=10,
                 coverage={"queried": 2, "responded": 2, "failed": 0, "not_found": 0})


@pytest.fixture
def no_providers(monkeypatch):
    """No provider or AI key, whatever the developer's shell has: nothing is sent."""
    for cls in _config_classes():
        for attr in ("VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "SHODAN_API_KEY",
                     "OTX_API_KEY", "GREYNOISE_API_KEY", "ZEROBOUNCE_API_KEY", "GROQ_API_KEY"):
            monkeypatch.setattr(cls, attr, "", raising=False)
        monkeypatch.setattr(cls, "AI_PROVIDER", "disabled", raising=False)


class TestEvidenceIsShown:
    """A 0/100 LOW without usable provider data must never read as a clean verdict."""

    def test_terminal_says_insufficient_data_instead_of_a_clean_mark(self):
        out = ReportGenerator().to_terminal(_evidence_result(**_NO_EVIDENCE), colour=False)
        assert "Evidence: insufficient data" in out
        assert "not a clean verdict" in out
        assert "✅" not in out

    def test_terminal_names_unavailable_providers_on_partial_coverage(self):
        out = ReportGenerator().to_terminal(_evidence_result(**_PARTIAL), colour=False)
        assert "Evidence: partial — 1/2 providers returned data" in out
        assert "unavailable: GreyNoise" in out

    def test_terminal_reports_complete_coverage(self):
        out = ReportGenerator().to_terminal(_evidence_result(**_COMPLETE), colour=False)
        assert "Evidence: complete — 2/2 providers returned data" in out

    @pytest.mark.parametrize("case", [_NO_EVIDENCE, _PARTIAL, _COMPLETE],
                             ids=["insufficient", "partial", "complete"])
    def test_table_has_evidence_rows(self, case):
        out = ReportGenerator().to_table(_evidence_result(**case))
        assert re.search(r"\| Evidence Status\s+\| " + case["status"], out)
        assert re.search(r"\| Providers With Data\s+\| \d+/\d+", out)

    def test_table_names_unavailable_providers_and_flags_missing_evidence(self):
        partial = ReportGenerator().to_table(_evidence_result(**_PARTIAL))
        assert re.search(r"\| Unavailable Providers\s+\| GreyNoise", partial)
        empty = ReportGenerator().to_table(_evidence_result(**_NO_EVIDENCE))
        assert "not a clean verdict" in empty

    def test_markdown_evidence_notes_are_in_the_report_language(self):
        md_empty = ReportGenerator().to_markdown(_evidence_result(**_NO_EVIDENCE))
        md_partial = ReportGenerator().to_markdown(_evidence_result(**_PARTIAL))
        assert "**Insufficient data:**" in md_empty
        assert "does not mean the IOC is safe" in md_empty
        assert "**Partial coverage:**" in md_partial and "GreyNoise" in md_partial
        for md in (md_empty, md_partial):
            assert "Yetersiz" not in md and "Kısmi" not in md

    def test_markdown_metrics_show_the_evidence_status(self):
        md = ReportGenerator().to_markdown(_evidence_result(**_PARTIAL))
        assert "| **Evidence Status** | partial (1/2 providers returned data) |" in md

    @pytest.mark.parametrize("render", ["to_json", "to_ndjson"])
    def test_json_formats_keep_the_evidence_fields(self, render):
        data = json.loads(getattr(ReportGenerator(), render)(_evidence_result(**_PARTIAL)))
        risk = data["risk_assessment"]
        assert risk["evidence_status"] == "partial"
        assert risk["unavailable_providers"] == ["GreyNoise"]
        assert risk["provider_coverage"]["responded"] == 1

    def test_cli_single_ioc_without_providers_says_insufficient_data(
            self, reports_dir, no_providers, capsys):
        from ioc_enricher.cli.main import main
        assert main(["--no-banner", "--no-cache", "--ioc", "203.0.113.7"]) == 0
        out = capsys.readouterr().out
        assert "Evidence: insufficient data" in out
        assert "✅" not in out

    def test_cli_batch_line_flags_insufficient_data(self, reports_dir, no_providers, tmp_path, capsys):
        from ioc_enricher.cli.main import main
        ioc_file = tmp_path / "iocs.txt"
        ioc_file.write_text("203.0.113.7\n", encoding="utf-8")
        assert main(["--no-banner", "--no-cache", "--file", str(ioc_file)]) == 0
        [line] = [ln for ln in capsys.readouterr().out.splitlines() if "203.0.113.7" in ln]
        assert "insufficient data" in line
        assert "✅" not in line


# ---------------------------------------------------------------------------
# Colour only for an interactive terminal, and never with NO_COLOR
# ---------------------------------------------------------------------------

class _Tty(io.StringIO):
    def isatty(self) -> bool:
        return True


class TestColour:

    def test_report_api_can_render_without_colour(self):
        plain = ReportGenerator().to_terminal(_result(), colour=False)
        assert ESC not in plain
        assert "\\x1b[2J" in plain                        # injected text is still made visible

    def test_colour_follows_the_terminal_and_no_color(self, monkeypatch):
        from ioc_enricher.cli.main import _use_colour
        monkeypatch.delenv("NO_COLOR", raising=False)
        assert _use_colour(_Tty()) is True
        assert _use_colour(io.StringIO()) is False
        monkeypatch.setenv("NO_COLOR", "1")
        assert _use_colour(_Tty()) is False

    def test_cli_output_is_plain_when_stdout_is_not_a_terminal(self, reports_dir, no_providers, capsys):
        from ioc_enricher.cli.main import main
        assert main(["--no-banner", "--no-cache", "--ioc", "203.0.113.7"]) == 0
        assert ESC not in capsys.readouterr().out

    @pytest.mark.parametrize("no_color, coloured", [(None, True), ("1", False)])
    def test_cli_colour_on_a_terminal_respects_no_color(
            self, reports_dir, no_providers, monkeypatch, no_color, coloured):
        from ioc_enricher.cli.main import main
        tty = _Tty()
        monkeypatch.setattr(sys, "stdout", tty)
        if no_color is None:
            monkeypatch.delenv("NO_COLOR", raising=False)
        else:
            monkeypatch.setenv("NO_COLOR", no_color)
        assert main(["--no-banner", "--no-cache", "--ioc", "203.0.113.7"]) == 0
        assert (ESC in tty.getvalue()) is coloured
