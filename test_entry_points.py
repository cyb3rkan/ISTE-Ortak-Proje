"""
The suite starts the same way with ``pytest`` and with ``python -m pytest``
(the command in AGENTS.md and CI), with or without the editable install.

``python -m pytest`` puts the current directory on ``sys.path``; run from the
repository root, the outer ``ioc_enricher/`` directory then looks like a
namespace package. ``tests/conftest.py`` must not take it for the real
package, or every import of ``ioc_enricher.web`` / ``ioc_enricher.core``
fails at collection. Only collection runs here: no test executes twice.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]


def test_python_dash_m_pytest_collects_both_test_trees_from_the_repository_root() -> None:
    env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "--collect-only", "-q",
         "tests/security/test_example_config.py", "ioc_enricher/tests/test_validator.py"],
        cwd=_ROOT, env=env, capture_output=True, text=True, timeout=180,
    )
    assert proc.returncode == 0, (proc.stdout + proc.stderr)[-3000:]


def test_the_suite_writes_no_app_log_file() -> None:
    # LOG_FILE defaults to logs/ioc_enricher.log under the working directory,
    # i.e. the real runtime log when run from the repository root.
    import logging

    from ioc_enricher.utils.logger import get_logger

    get_logger("tests.hermetic").warning("hermetic suite probe")
    handlers = logging.getLogger("ioc_enricher").handlers
    assert not any(isinstance(h, logging.FileHandler) for h in handlers)
