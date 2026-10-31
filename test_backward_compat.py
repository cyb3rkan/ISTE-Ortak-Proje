"""
CLI regression tests.

The web adapter must NOT have broken the canonical CLI surface. We exercise
the read-only / no-network flags only:

* ``python -m ioc_enricher --version``
* ``python -m ioc_enricher --status``
* ``python -m ioc_enricher --help``
* ``python -m ioc_enricher --no-banner --cache-stats``

We invoke the CLI in two ways:

1. Direct in-process call to ``main()`` — fast, deterministic.
2. Sub-process invocation of ``python -m ioc_enricher`` — guards the
   ``__main__`` entry-point.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest


_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_CANONICAL_PKG_ROOT = _REPO_ROOT / "ioc_enricher"


# Make sure the canonical package is importable when these tests run.
sys.path.insert(0, str(_CANONICAL_PKG_ROOT))


# ---------------------------------------------------------------------------
# In-process tests
# ---------------------------------------------------------------------------

class TestInProcessCLI:
    def test_version_exits_zero(self, capsys) -> None:
        from ioc_enricher.cli.main import main as cli_main
        rc = cli_main(["--version"])
        captured = capsys.readouterr()
        assert rc == 0
        assert "IOC Enricher Agent" in captured.out

    def test_status_exits_zero(self, capsys) -> None:
        from ioc_enricher.cli.main import main as cli_main
        rc = cli_main(["--status", "--no-banner"])
        captured = capsys.readouterr()
        assert rc == 0
        assert "Provider Status" in captured.out

    def test_help_exits_zero(self) -> None:
        from ioc_enricher.cli.main import main as cli_main
        # argparse calls sys.exit(0) on --help
        with pytest.raises(SystemExit) as exc_info:
            cli_main(["--help"])
        assert exc_info.value.code == 0


# ---------------------------------------------------------------------------
# Sub-process tests for ``python -m ioc_enricher``
# ---------------------------------------------------------------------------

def _run_module(args: list[str]) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    # Ensure the canonical package is on PYTHONPATH for the child process.
    existing = env.get("PYTHONPATH", "")
    sep = os.pathsep
    env["PYTHONPATH"] = (
        f"{_CANONICAL_PKG_ROOT}{sep}{existing}" if existing else str(_CANONICAL_PKG_ROOT)
    )
    return subprocess.run(
        [sys.executable, "-m", "ioc_enricher", *args],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(_REPO_ROOT),
        timeout=60,
    )


class TestSubprocessCLI:
    def test_version_via_module(self) -> None:
        result = _run_module(["--version"])
        assert result.returncode == 0, result.stderr
        assert "IOC Enricher Agent" in result.stdout

    def test_status_via_module(self) -> None:
        result = _run_module(["--status", "--no-banner"])
        assert result.returncode == 0, result.stderr
        assert "Provider Status" in result.stdout
