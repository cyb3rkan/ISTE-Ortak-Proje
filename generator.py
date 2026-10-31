"""
Report generation module.

Produces reports in JSON and Markdown formats from an EnrichmentResult,
plus a coloured terminal summary.

Usage:
    from ioc_enricher.reports.generator import ReportGenerator

    gen = ReportGenerator()
    md  = gen.to_markdown(result)
    js  = gen.to_json(result)
    gen.save(result, "markdown")   # → reports/<name>.md
"""
from __future__ import annotations

import json
import os
import re
import secrets
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from ..models.result import EnrichmentResult, RiskLevel
from ..utils.config import Config
from ..utils.fileio import private_dir
from ..utils.logger import get_logger

log = get_logger(__name__)

OutputFormat = Literal["json", "markdown", "terminal", "table", "ndjson"]

# ---------------------------------------------------------------------------
# ANSI colour helpers (terminal only)
# ---------------------------------------------------------------------------

_C = {
    "RED": "\033[91m",
    "GREEN": "\033[92m",
    "YELLOW": "\033[93m",
    "CYAN": "\033[96m",
    "MAGENTA": "\033[95m",
    "WHITE": "\033[97m",
    "BOLD": "\033[1m",
    "RESET": "\033[0m",
}
# The same keys without escape codes: pipes, files and NO_COLOR.
_NO_C = {key: "" for key in _C}

_LEVEL_COLOUR = {
    RiskLevel.LOW: _C["GREEN"],
    RiskLevel.MEDIUM: _C["YELLOW"],
    RiskLevel.HIGH: _C["YELLOW"],
    RiskLevel.CRITICAL: _C["RED"],
}

_LEVEL_EMOJI = {
    RiskLevel.LOW: "✅",
    RiskLevel.MEDIUM: "⚠️",
    RiskLevel.HIGH: "🔴",
    RiskLevel.CRITICAL: "🚨",
}

# Simple pattern to sanitise text before embedding in reports
_UNSAFE_MD = re.compile(r"[`<>]")

# Control (C0/C1, incl. ESC, BEL, CR), invisible formatting (bidi overrides,
# zero-width) and line/paragraph separator characters.
_UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp", "Cs"})


def _is_unsafe(ch: str) -> bool:
    return unicodedata.category(ch) in _UNSAFE_CATEGORIES


def _term_safe(value: object, multiline: bool = False) -> str:
    """
    Make untrusted text (provider fields, AI output, IOCs) inert in a terminal.

    ESC-based CSI/OSC sequences can clear the screen, retitle the window or
    fake colours; CR and bidi overrides can make a line read differently from
    what it says. Such characters are shown as visible escapes (``\\x1b``,
    ``\\u202e``); every other character is unchanged. Newlines are kept only
    for multi-line blocks.
    """
    text = str(value)
    if text.isprintable():
        return text
    out = []
    for ch in text:
        if (ch == "\n" and multiline) or not _is_unsafe(ch):
            out.append(ch)
        elif ord(ch) <= 0xFF:
            out.append(f"\\x{ord(ch):02x}")
        elif ord(ch) <= 0xFFFF:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(f"\\U{ord(ch):08x}")
    return "".join(out)


# Public name for the CLI, which echoes IOCs and error text.
terminal_safe = _term_safe


def _json_safe(text: str) -> str:
    """
    JSON text with C1/bidi/zero-width characters as ``\\uXXXX`` escapes.

    ``json.dumps`` already escapes C0 controls inside strings (so any raw
    ASCII newline is layout); this covers the rest, so the output is still
    valid JSON and decodes to the very same values.
    """
    if text.isascii():
        return text
    out = []
    for ch in text:
        if ch.isascii() or not _is_unsafe(ch):
            out.append(ch)
            continue
        cp = ord(ch)
        if cp > 0xFFFF:
            cp -= 0x10000
            out.append(f"\\u{0xD800 + (cp >> 10):04x}\\u{0xDC00 + (cp & 0x3FF):04x}")
        else:
            out.append(f"\\u{cp:04x}")
    return "".join(out)


def _safe(text: str) -> str:
    """Strip characters that could cause Markdown or HTML injection; neutralise terminal controls."""
    return _term_safe(_UNSAFE_MD.sub("", str(text)), multiline=True)


def _coverage(rs) -> tuple[int, int, int, list[str]]:
    """``(queried, responded, not_found, unavailable providers)`` of a risk score."""
    counts = getattr(rs, "provider_coverage", None) or {}

    def _count(key: str) -> int:
        try:
            return int(counts.get(key, 0) or 0)
        except (TypeError, ValueError):
            return 0

    unavailable = [str(n) for n in (getattr(rs, "unavailable_providers", None) or [])]
    return _count("queried"), _count("responded"), _count("not_found"), unavailable


def _evidence_text(rs) -> str | None:
    """
    One line saying how much evidence the score rests on, or ``None`` when
    the result carries no evidence status. A score without usable provider
    data is said to be no verdict, so 0/100 LOW never reads as "clean".
    """
    status = getattr(rs, "evidence_status", None)
    if not status:
        return None
    queried, responded, not_found, unavailable = _coverage(rs)
    if status == "insufficient_data":
        what = "no provider was queried" if not queried else "no provider returned usable data"
        return f"insufficient data — {what}; this score is not a clean verdict."
    counts = f"{responded}/{queried} providers returned data"
    if not_found:
        counts += f" ({not_found} without a record)"
    if status == "partial":
        return f"partial — {counts}; unavailable: {', '.join(unavailable) or 'unknown'}."
    return f"{status} — {counts}."


# An explicit report file stem: a plain name that stays inside REPORTS_DIR.
_STEM = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")


class ReportGenerator:
    """Generate reports in multiple formats from an EnrichmentResult."""

    # ------------------------------------------------------------------
    # Public methods
    # ------------------------------------------------------------------

    def to_json(self, result: EnrichmentResult) -> str:
        """Serialise *result* to a pretty-printed JSON string."""
        return _json_safe(json.dumps(result.to_dict(), indent=2, ensure_ascii=False, default=str))

    def to_ndjson(self, result: EnrichmentResult) -> str:
        """Serialise *result* as a single newline-delimited JSON record."""
        return _json_safe(json.dumps(result.to_dict(), ensure_ascii=False, default=str))

    def to_table(self, result: EnrichmentResult) -> str:
        """
        Render *result* as a compact plain-text table suitable for terminal
        piping or CI output.  No ANSI codes.
        """
        r = result
        rs = r.risk_score
        lines: list[str] = []

        sep = "+" + "-" * 30 + "+" + "-" * 40 + "+"
        def row(label: str, value: str) -> str:
            return f"| {_term_safe(label):<28} | {_term_safe(value):<38} |"

        lines += [
            sep,
            row("IOC", r.ioc),
            row("Type", r.ioc_type.value.upper()),
            row("Timestamp", r.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")),
            row("From Cache", "Yes" if r.from_cache else "No"),
            sep,
            row("Risk Score", f"{rs.score}/100"),
            row("Risk Level", rs.level.value),
            row("Detection Confidence", f"{rs.detection_confidence:.0%}"),
        ]

        evidence_status = getattr(rs, "evidence_status", None)
        if evidence_status:
            queried, responded, _, unavailable = _coverage(rs)
            lines += [
                row("Evidence Status", evidence_status),
                row("Providers With Data", f"{responded}/{queried}"),
            ]
            if unavailable:
                lines.append(row("Unavailable Providers", ", ".join(unavailable)))
            if evidence_status == "insufficient_data":
                lines.append(row("Note", "No usable data; not a clean verdict"))

        if r.ai_analysis:
            ai = r.ai_analysis
            lines += [
                row("AI Confidence", f"{ai.ai_confidence:.0%}"),
                row("Human Review Required", "YES" if ai.requires_human_review else "No"),
            ]

        lines.append(sep)
        lines.append(row("Active Data Points", str(len(rs.active_data_points))))

        # Score breakdown
        lines += [
            sep,
            row("  VirusTotal", str(rs.breakdown.virustotal)),
            row("  AbuseIPDB", str(rs.breakdown.abuseipdb)),
            row("  OTX", str(rs.breakdown.otx)),
            row("  Shodan", str(rs.breakdown.shodan)),
            row("  GreyNoise", str(rs.breakdown.greynoise)),
            row("  ZeroBounce", str(rs.breakdown.zerobounce)),
            sep,
        ]

        # Provider status
        for pname, pres in r.provider_results.items():
            status = "OK" if pres.is_success() else pres.status.value.upper()
            lines.append(row(f"  {pname}", f"{status} ({pres.response_time:.2f}s)"))
        lines.append(sep)

        # MITRE
        for m in r.mitre_mappings:
            lines.append(row(f"  {m.technique_id}", m.technique_name))
        if r.mitre_mappings:
            lines.append(sep)

        # Prioritized recommendations
        if r.ai_analysis and r.ai_analysis.prioritized_recommendations:
            for rec in r.ai_analysis.prioritized_recommendations[:5]:
                lines.append(row(f"  [{rec.priority.upper()}]", rec.action[:38]))
            lines.append(sep)

        return "\n".join(lines)

    def to_markdown(self, result: EnrichmentResult) -> str:
        """Render *result* as a Markdown document."""
        r = result
        rs = r.risk_score
        emoji = _LEVEL_EMOJI.get(rs.level, "ℹ️")
        lines: list[str] = []

        # Header
        lines += [
            "# 🔍 IOC Enrichment Report",
            "",
            "---",
            "",
            "## 📋 Overview",
            "",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| **IOC** | `{_safe(r.ioc)}` |",
            f"| **Type** | {r.ioc_type.value.upper()} |",
            f"| **Timestamp** | {r.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')} |",
            f"| **From Cache** | {'Yes' if r.from_cache else 'No'} |",
            f"| **Execution Time** | {r.execution_time:.2f}s |",
            "",
        ]

        # Risk assessment
        lines += [
            "---",
            "",
            "## 🎯 Risk Assessment",
            "",
            f"### {emoji} Score: {rs.score}/100 — {rs.level.value}",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| **Detection Confidence** | {rs.detection_confidence:.0%} |",
        ]
        if getattr(rs, "evidence_status", None):
            queried, responded, _, _ = _coverage(rs)
            lines.append(
                f"| **Evidence Status** | {_safe(rs.evidence_status)} "
                f"({responded}/{queried} providers returned data) |"
            )

        if r.ai_analysis:
            ai = r.ai_analysis
            lines += [
                f"| **AI Confidence** | {ai.ai_confidence:.0%} |",
                f"| **Human Review Required** | {'⚠️ YES' if ai.requires_human_review else 'No'} |",
            ]
        lines.append("")

        if rs.reasons:
            lines.append("**Evidence (active data points):**")
            lines.append("")
            for reason in rs.reasons:
                lines.append(f"- {_safe(reason)}")
            lines.append("")

        if rs.active_data_points:
            lines.append("**Raw signals used:**")
            lines.append("")
            for dp in rs.active_data_points:
                lines.append(f"  - `{_safe(dp)}`")
            lines.append("")

        # Score breakdown table
        bd = rs.breakdown
        lines += [
            "**Score Breakdown:**",
            "",
            "| Provider | Points |",
            "|----------|--------|",
            f"| VirusTotal | {bd.virustotal} |",
            f"| AbuseIPDB | {bd.abuseipdb} |",
            f"| AlienVault OTX | {bd.otx} |",
            f"| Shodan | {bd.shodan} |",
            f"| GreyNoise | {bd.greynoise} |",
            f"| ZeroBounce | {bd.zerobounce} |",
        ]
        # Non-provider deterministic components, so the table sums to Total.
        for adj in getattr(rs, "score_adjustments", []) or []:
            lines.append(f"| _{_safe(adj.label)}_ | {adj.points:+d} |")
        lines += [
            f"| **Total** | **{rs.score}** |",
            "",
        ]
        evidence_status = getattr(rs, "evidence_status", None)
        if evidence_status == "insufficient_data":
            lines += [
                "> ⚠️ **Insufficient data:** no provider returned usable data. "
                "A low score does not mean the IOC is safe.",
                "",
            ]
        elif evidence_status == "partial":
            names = ", ".join(getattr(rs, "unavailable_providers", []) or [])
            lines += [
                f"> ℹ️ **Partial coverage:** providers that did not answer: {_safe(names)}. "
                "Provider failures do not change the score.",
                "",
            ]

        # MITRE ATT&CK
        if r.mitre_mappings:
            lines += [
                "---",
                "",
                "## 🛡️ MITRE ATT&CK Mapping",
                "",
                "| Tactic | Technique ID | Technique Name |",
                "|--------|-------------|----------------|",
            ]
            for m in r.mitre_mappings:
                lines.append(
                    f"| {_safe(m.tactic)} | {_safe(m.technique_id)} | {_safe(m.technique_name)} |"
                )
            lines.append("")
            for m in r.mitre_mappings:
                lines += [
                    f"**{_safe(m.technique_id)} — {_safe(m.technique_name)}**",
                    f"> {_safe(m.description)}",
                ]
                if getattr(m, "evidence", ""):
                    lines.append(
                        f"> Dayanak ({_safe(getattr(m, 'basis', 'reported'))}): "
                        f"{_safe(m.evidence)}"
                    )
                lines.append("")

        # Provider results
        lines += ["---", "", "## 📊 Provider Results", ""]
        for pname, pres in r.provider_results.items():
            status_icon = "✅" if pres.is_success() else "❌"
            lines += [f"### {status_icon} {_safe(pname)}", ""]
            lines.append(f"**Status:** `{_safe(pres.status.value)}` | **Response time:** {pres.response_time:.2f}s")
            lines.append("")
            if pres.is_success() and pres.data:
                lines.append("```json")
                # _safe(): provider text must not close the fence (``` ) or
                # smuggle HTML into the rendered report.
                lines.append(_safe(json.dumps(pres.data, indent=2, ensure_ascii=False, default=str)))
                lines.append("```")
            elif pres.error:
                lines.append(f"**Error:** {_safe(pres.error)}")
            lines.append("")

        # AI analysis (optional)
        if r.ai_analysis:
            ai = r.ai_analysis
            lines += [
                "---",
                "",
                f"## 🤖 AI Analysis _(provider: {_safe(ai.ai_provider)})_",
                "",
                f"> {_safe(ai.summary)}",
                "",
            ]
            if ai.analyst_note:
                lines += [
                    "**Analyst Note:**",
                    "",
                    f"> _{_safe(ai.analyst_note)}_",
                    "",
                ]
            if ai.requires_human_review:
                lines += [
                    "> ⚠️ **Human review recommended** — evidence is ambiguous or conflicting.",
                    "",
                ]
            if ai.why_malicious:
                lines.append("**Why this could be malicious:**")
                lines.append("")
                for w in ai.why_malicious:
                    lines.append(f"- 🔴 {_safe(w)}")
                lines.append("")
            if ai.why_benign:
                lines.append("**Why this could be benign:**")
                lines.append("")
                for w in ai.why_benign:
                    lines.append(f"- 🟢 {_safe(w)}")
                lines.append("")
            if ai.weak_signals:
                lines.append("**Weak signals / contradictions:**")
                lines.append("")
                for ws in ai.weak_signals:
                    lines.append(f"- ⚡ `{_safe(ws.signal_type)}` — {_safe(ws.message)}")
                lines.append("")
            if ai.key_findings:
                lines.append("**Key Findings:**")
                lines.append("")
                for f_ in ai.key_findings:
                    lines.append(f"- {_safe(f_)}")
                lines.append("")
            if ai.prioritized_recommendations:
                _prio_icon = {"critical": "🚨", "high": "🔴", "medium": "🟡", "low": "🟢"}
                lines.append("**Prioritized Recommendations:**")
                lines.append("")
                lines += ["| Priority | Action | Rationale |", "|----------|--------|-----------|"]
                for rec in ai.prioritized_recommendations:
                    icon = _prio_icon.get(rec.priority.lower(), "•")
                    lines.append(
                        f"| {icon} {_safe(rec.priority.upper())} | {_safe(rec.action)} | {_safe(rec.rationale)} |"
                    )
                lines.append("")
            elif ai.recommendations:
                lines.append("**Recommendations:**")
                lines.append("")
                for rec in ai.recommendations:
                    lines.append(f"- {_safe(rec)}")
                lines.append("")
            if ai.tags:
                lines.append("**Tags:** " + " ".join(f"`{_safe(t)}`" for t in ai.tags))
                lines.append("")

        lines += ["---", "", "*Generated by IOC Enricher Agent*"]
        return "\n".join(lines)

    def to_terminal(self, result: EnrichmentResult, colour: bool = True) -> str:
        """
        Render *result* as a human-readable terminal string.

        With ``colour=False`` no ANSI escape code is written (the CLI turns
        colour off for pipes, files and ``NO_COLOR``).
        """
        r = result
        rs = r.risk_score
        c = _C if colour else _NO_C
        level_c = _LEVEL_COLOUR.get(rs.level, c["WHITE"]) if colour else ""
        evidence = _evidence_text(rs)
        no_evidence = getattr(rs, "evidence_status", None) == "insufficient_data"
        # A green tick next to a score nothing supports would read as "clean".
        emoji = "❔" if no_evidence else _LEVEL_EMOJI.get(rs.level, "ℹ️")
        lines: list[str] = []

        sep = f"{c['BOLD']}{'═' * 70}{c['RESET']}"
        thin = f"{c['BOLD']}{'─' * 70}{c['RESET']}"

        lines += [
            "",
            sep,
            f"{c['BOLD']}{c['CYAN']}   🔍 IOC ENRICHMENT REPORT{c['RESET']}",
            sep,
            "",
            f"{c['BOLD']}IOC   :{c['RESET']}  {_term_safe(r.ioc)}",
            f"{c['BOLD']}Type  :{c['RESET']}  {r.ioc_type.value.upper()}",
            f"{c['BOLD']}Time  :{c['RESET']}  {r.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "",
            thin,
            f"{c['BOLD']}🎯  RISK SCORE:{c['RESET']}  "
            f"{level_c}{c['BOLD']}{rs.score}/100{c['RESET']}  "
            f"{emoji}  {level_c}{c['BOLD']}{rs.level.value}{c['RESET']}",
            f"    Detection Confidence: {rs.detection_confidence:.0%}",
        ]
        if evidence:
            ev_c = c["YELLOW"] if rs.evidence_status in ("insufficient_data", "partial") else ""
            lines.append(f"    {ev_c}Evidence: {_term_safe(evidence)}{c['RESET'] if ev_c else ''}")
        lines += [
            thin,
            "",
        ]

        # Human review warning
        if r.ai_analysis and r.ai_analysis.requires_human_review:
            lines.append(
                f"  {c['YELLOW']}⚠️  HUMAN REVIEW RECOMMENDED — evidence is ambiguous{c['RESET']}"
            )
            lines.append("")

        # Score reasons
        if rs.reasons:
            for reason in rs.reasons:
                lines.append(f"  • {_term_safe(reason)}")
            lines.append("")

        # Why malicious / why benign
        if r.ai_analysis:
            ai = r.ai_analysis
            # These lines sit right under the deterministic reasons, so
            # model-written ones are labelled as such.
            source = " (AI narrative)" if ai.ai_provider not in ("", "none") else ""
            if ai.why_malicious:
                lines.append(f"  {c['RED']}↑ Why malicious{source}:{c['RESET']}")
                for w in ai.why_malicious[:3]:
                    lines.append(f"    - {_term_safe(w)}")
            if ai.why_benign:
                lines.append(f"  {c['GREEN']}↓ Why benign{source}:{c['RESET']}")
                for w in ai.why_benign[:3]:
                    lines.append(f"    - {_term_safe(w)}")
            if ai.weak_signals:
                lines.append(f"  {c['YELLOW']}⚡ Weak signals{source}:{c['RESET']}")
                for ws in ai.weak_signals[:3]:
                    lines.append(f"    - [{_term_safe(ws.signal_type)}] {_term_safe(ws.message)}")
            lines.append("")

        # Provider results
        lines.append(f"{c['BOLD']}{c['CYAN']}📊 PROVIDER RESULTS{c['RESET']}")
        lines.append(thin)
        for pname, pres in r.provider_results.items():
            if pres.is_success():
                icon = f"{c['GREEN']}✓{c['RESET']}"
                lines.append(f"\n{icon} {c['BOLD']}{_term_safe(pname)}{c['RESET']}  ({pres.response_time:.2f}s)")
                if pres.data:
                    for k, v in list(pres.data.items())[:8]:
                        if v not in (None, [], {}, ""):
                            lines.append(f"  └─ {_term_safe(k)}: {_term_safe(str(v)[:80])}")
            else:
                icon = f"{c['RED']}✗{c['RESET']}"
                lines.append(f"\n{icon} {c['BOLD']}{_term_safe(pname)}{c['RESET']}  [{pres.status.value}]")
                if pres.error:
                    lines.append(f"  └─ {_term_safe(pres.error[:100])}")

        lines.append("")

        # MITRE ATT&CK
        if r.mitre_mappings:
            lines.append(f"{c['BOLD']}{c['MAGENTA']}🛡️  MITRE ATT&CK{c['RESET']}")
            lines.append(thin)
            for m in r.mitre_mappings:
                lines.append(
                    f"  {c['CYAN']}{_term_safe(m.technique_id)}{c['RESET']}  "
                    f"{_term_safe(m.tactic)} → {_term_safe(m.technique_name)}"
                )
            lines.append("")

        # AI analysis
        if r.ai_analysis and r.ai_analysis.summary:
            ai = r.ai_analysis
            lines.append(f"{c['BOLD']}{c['MAGENTA']}🤖 AI ANALYSIS{c['RESET']}")
            lines.append(thin)
            lines.append(f"\n{_term_safe(ai.summary, multiline=True)}\n")
            if ai.analyst_note:
                lines.append(
                    f"  {c['CYAN']}Analyst note:{c['RESET']} {_term_safe(ai.analyst_note, multiline=True)}\n"
                )
            if ai.prioritized_recommendations:
                _prio_c = {
                    "critical": c["RED"], "high": c["YELLOW"],
                    "medium": c["WHITE"], "low": c["GREEN"],
                }
                lines.append(f"{c['BOLD']}Prioritized Recommendations:{c['RESET']}")
                for rec in ai.prioritized_recommendations[:5]:
                    pc = _prio_c.get(rec.priority.lower(), c["WHITE"])
                    lines.append(
                        f"  {pc}[{_term_safe(rec.priority.upper())}]{c['RESET']} {_term_safe(rec.action)}"
                    )
                    if rec.rationale:
                        lines.append(f"         → {_term_safe(rec.rationale)}")
            elif ai.recommendations:
                lines.append(f"{c['BOLD']}Recommendations:{c['RESET']}")
                for rec in ai.recommendations:
                    lines.append(f"  • {_term_safe(rec)}")
            # Audit trail
            if ai.audit_trail:
                at = ai.audit_trail
                lines.append(
                    f"\n  {c['CYAN']}AI audit:{c['RESET']} model={_term_safe(at.model)} "
                    f"tokens={at.prompt_tokens}+{at.completion_tokens} "
                    f"latency={at.latency_s:.2f}s "
                    f"redacted={len(at.fields_redacted)} fields"
                )
            lines.append("")

        lines += [sep, ""]
        return "\n".join(lines)

    # ------------------------------------------------------------------

    def save(
        self,
        result: EnrichmentResult,
        fmt: OutputFormat,
        stem: str | None = None,
    ) -> Path:
        """
        Write the report to a new file in *reports/* and return the path.

        The default name is ``ioc_<type>_<UTC time>_<random>.<ext>``: it never
        contains the IOC itself (file names end up in listings, shell history
        and backup/sync logs). An existing file is never overwritten: a clash
        draws a new random suffix, and an explicit *stem* that already exists
        raises :class:`FileExistsError`.

        Args:
            result: Enrichment result to serialise.
            fmt:    "json", "markdown", "table" or "ndjson".
            stem:   Optional plain file name stem (letters, digits, ``._-``).

        Returns:
            Path to the written file (owner-only on POSIX).
        """
        renderers = {
            "json": (self.to_json, "json"),
            "markdown": (self.to_markdown, "md"),
            "table": (self.to_table, "txt"),
            "ndjson": (self.to_ndjson, "ndjson"),
        }
        if fmt not in renderers:
            raise ValueError(f"Unsupported report format: {fmt!r}")
        if stem is not None and not (_STEM.fullmatch(stem) and ".." not in stem):
            raise ValueError("Report stem must be a plain file name (letters, digits, '._-').")
        render, ext = renderers[fmt]
        content = render(result)

        private_dir(Config.REPORTS_DIR)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        for _ in range(16):
            name = stem or f"ioc_{result.ioc_type.value}_{ts}_{secrets.token_hex(4)}"
            path = Config.REPORTS_DIR / f"{name}.{ext}"
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                if stem is not None:
                    raise
                continue
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(content)
            # The caller gets the path; the log line stays free of paths.
            log.info("Report saved (%s).", fmt)
            return path
        raise FileExistsError("No free report file name found.")
