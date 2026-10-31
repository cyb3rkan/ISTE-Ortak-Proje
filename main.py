#!/usr/bin/env python3
"""
IOC Enricher Agent — Command-Line Interface

Usage examples:
    python -m ioc_enricher --ip 8.8.8.8
    python -m ioc_enricher --domain malicious.example.com --save markdown
    python -m ioc_enricher --hash 44d88612fea8a8f36de82e1278abb02f
    python -m ioc_enricher --url https://evil.example.com/payload.exe
    python -m ioc_enricher --email phisher@evil.example.com
    python -m ioc_enricher --ioc 1.2.3.4                   # auto-detect type
    python -m ioc_enricher --file iocs.txt --save json
    python -m ioc_enricher --status
    python -m ioc_enricher --cache-stats
    python -m ioc_enricher --clear-cache
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Ensure the project root is on the path when called as a script
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from ioc_enricher import IOCEnricher, __version__
from ioc_enricher.reports.generator import ReportGenerator, terminal_safe
from ioc_enricher.utils.cache import Cache
from ioc_enricher.utils.config import Config
from ioc_enricher.utils.logger import wants_colour


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

_BANNER = r"""
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║          IOC ENRICHER AGENT  v{ver:<10}                          ║
║          Threat Intelligence Enrichment & Risk Scoring               ║
║                                                                      ║
║  Providers: VirusTotal · AbuseIPDB · Shodan · OTX · GreyNoise        ║
║             ZeroBounce (+ optional AI layer: Groq)                  ║
╚══════════════════════════════════════════════════════════════════════╝
"""


def _print_banner() -> None:
    print(_BANNER.format(ver=__version__))


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------

def _print_provider_status(enricher: IOCEnricher) -> None:
    status = enricher.provider_status()
    cfg_status = Config.provider_status()
    print("\n📡 Provider Status")
    print("─" * 45)
    for name, cfg_enabled in cfg_status.items():
        # TI providers are "active" when instantiated; the AI layer is not in
        # enricher.provider_status(), so fall back to its configured state.
        active = (name in status) or (cfg_enabled and "AI layer" in name)
        icon = "✅" if cfg_enabled else "❌"
        label = "Active" if active else ("No API key" if not cfg_enabled else "Disabled")
        print(f"  {icon}  {name:<25} {label}")
    print()


def _use_colour(stream) -> bool:
    """ANSI colours only on an interactive terminal and never with NO_COLOR, as for the log."""
    return wants_colour(stream)


def _print_result_terminal(result, reporter: ReportGenerator) -> None:
    print(reporter.to_terminal(result, colour=_use_colour(sys.stdout)))


def _evidence_note(result) -> str:
    """Batch-line suffix: a score without usable provider data is no verdict."""
    rs = result.risk_score
    status = getattr(rs, "evidence_status", None)
    if status == "insufficient_data":
        return "  (insufficient data — not a clean verdict)"
    if status == "partial":
        unavailable = len(getattr(rs, "unavailable_providers", None) or [])
        return f"  (partial: {unavailable} provider(s) unavailable)"
    return ""


def _read_ioc_file(path: str) -> list[str]:
    file = Path(path)
    if not file.exists():
        print(f"❌ File not found: {terminal_safe(path)}", file=sys.stderr)
        sys.exit(1)
    iocs = [
        line.strip()
        for line in file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    if not iocs:
        print(f"❌ No valid IOCs found in file: {terminal_safe(path)}", file=sys.stderr)
        sys.exit(1)
    return iocs


def _save_report(reporter: ReportGenerator, result, fmt: str | None) -> str:
    """Save *result* when ``--save`` was given; the text that reports where."""
    if not fmt:
        return ""
    return f"💾 Report saved: {reporter.save(result, fmt)}"  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    """Entry point.  Returns an exit code."""
    parser = argparse.ArgumentParser(
        prog="ioc-enricher",
        description="IOC Enricher Agent — Threat Intelligence Enrichment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # --- IOC input (mutually exclusive) ---
    ioc_group = parser.add_mutually_exclusive_group()
    ioc_group.add_argument("--ip",     metavar="ADDRESS", help="IPv4 or IPv6 address")
    ioc_group.add_argument("--domain", metavar="DOMAIN",  help="Domain name")
    ioc_group.add_argument("--hash",   metavar="HASH",    help="File hash (MD5/SHA1/SHA256)")
    ioc_group.add_argument("--url",    metavar="URL",     help="URL")
    ioc_group.add_argument("--email",  metavar="EMAIL",   help="Email address")
    ioc_group.add_argument("--ioc",    metavar="IOC",     help="Any IOC (auto-detect type)")
    ioc_group.add_argument("--file",   metavar="FILE",    help="File with one IOC per line")

    # --- Output ---
    parser.add_argument(
        "--save",
        choices=["json", "markdown", "table", "ndjson"],
        metavar="FORMAT",
        help="Save report to file (json, markdown, table, ndjson)",
    )
    parser.add_argument(
        "--output",
        metavar="FORMAT",
        choices=["terminal", "json", "markdown", "table", "ndjson"],
        default="terminal",
        help="Print format for single-IOC analysis (default: terminal)",
    )

    # --- Cache ---
    parser.add_argument("--no-cache",    action="store_true", help="Bypass cache for this run")
    parser.add_argument("--clear-cache", action="store_true", help="Clear all cached results and exit")
    parser.add_argument("--cache-stats", action="store_true", help="Show cache statistics and exit")

    # --- Misc ---
    parser.add_argument("--status",    action="store_true", help="Show provider status and exit")
    parser.add_argument("--no-banner", action="store_true", help="Suppress the banner")
    parser.add_argument("--version",   action="store_true", help="Print version and exit")

    args = parser.parse_args(argv)

    # --- Version ---
    if args.version:
        print(f"IOC Enricher Agent {__version__}")
        return 0

    # Runtime directories are created here, at start-up — never on import.
    failed_dirs = Config.create_directories()
    if failed_dirs:
        print(
            f"⚠️  Could not create runtime directories: {', '.join(failed_dirs)}",
            file=sys.stderr,
        )

    if not args.no_banner:
        _print_banner()

    # --- Cache utilities (no enricher needed) ---
    cache = Cache()
    if args.clear_cache:
        n = cache.clear()
        print(f"🗑️  Cache cleared — {n} entry(s) removed.")
        return 0
    if args.cache_stats:
        stats = cache.stats()
        print("📦 Cache Statistics")
        print("─" * 35)
        for k, v in stats.items():
            print(f"  {k:<25} {v}")
        return 0

    # --- Initialise enricher ---
    try:
        enricher = IOCEnricher(cache=cache)
    except Exception as exc:
        print(f"❌ Initialisation failed: {terminal_safe(exc)}", file=sys.stderr)
        return 1

    # --- Provider status ---
    if args.status:
        _print_provider_status(enricher)
        return 0

    # --- Require at least one IOC input ---
    if not any([args.ip, args.domain, args.hash, args.url, args.email, args.ioc, args.file]):
        parser.print_help()
        print("\n❌ Error: please provide an IOC to analyse.", file=sys.stderr)
        return 1

    reporter = ReportGenerator()
    use_cache = not args.no_cache

    # ---------------------------------------------------------------
    # Batch mode
    # ---------------------------------------------------------------
    if args.file:
        iocs = _read_ioc_file(args.file)
        print(f"📂 Processing {len(iocs)} IOC(s) from {terminal_safe(args.file)} …\n")
        # The CLI saves the reports itself so it can say where each one went.
        results = enricher.enrich_batch(iocs, use_cache=use_cache)

        success = 0
        for raw, res in zip(iocs, results):
            if isinstance(res, Exception):
                print(f"  ❌ {terminal_safe(raw)}  →  {terminal_safe(res)}")
            else:
                icon = "🚨" if res.risk_score.score > 80 else "⚠️" if res.risk_score.score > 50 else "✅"
                if getattr(res.risk_score, "evidence_status", None) == "insufficient_data":
                    icon = "❔"
                print(f"  {icon} {terminal_safe(raw):<45}  score={res.risk_score.score:>3}  "
                      f"{res.risk_score.level.value}{_evidence_note(res)}")
                saved = _save_report(reporter, res, args.save)
                if saved:
                    print(f"     {saved}")
                success += 1

        print(f"\n✅ Done — {success}/{len(iocs)} IOC(s) enriched successfully.")
        return 0

    # ---------------------------------------------------------------
    # Single IOC mode
    # ---------------------------------------------------------------
    raw = args.ip or args.domain or args.hash or args.url or args.email or args.ioc

    try:
        print(f"🔍 Analysing: {terminal_safe(raw)}\n")
        result = enricher.enrich(raw, use_cache=use_cache)
    except ValueError as exc:
        print(f"❌ Validation error: {terminal_safe(exc)}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"❌ Enrichment failed: {terminal_safe(exc)}", file=sys.stderr)
        return 1

    # Output
    if args.output == "json":
        print(reporter.to_json(result))
    elif args.output == "markdown":
        print(reporter.to_markdown(result))
    elif args.output == "table":
        print(reporter.to_table(result))
    elif args.output == "ndjson":
        print(reporter.to_ndjson(result))
    else:
        _print_result_terminal(result, reporter)

    saved = _save_report(reporter, result, args.save)
    if saved:
        print(saved)
    print(f"⏱️  Completed in {result.execution_time:.2f}s")
    if result.from_cache:
        print("💾 Result served from cache.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
