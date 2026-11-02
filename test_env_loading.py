"""
Explicit, predictable .env loading (utils.config.load_env_file).

Rules under test:
* ``IOC_ENRICHER_DOTENV`` unset   -> only ``<cwd>/.env`` is loaded; parent
  directories are never searched.
* ``IOC_ENRICHER_DOTENV=<path>``  -> exactly that file is loaded.
* ``IOC_ENRICHER_DOTENV=0|false|off|none`` -> nothing is loaded.
* Variables already in the environment always win (Docker / CI precedence).

Every test uses throw-away files in ``tmp_path``; no real .env is touched.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from ioc_enricher.utils.config import load_env_file


@pytest.fixture()
def environ() -> dict:
    return {}


def _write(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    return path


class TestDefaultCwdOnly:
    def test_loads_dotenv_from_cwd(self, tmp_path: Path, environ: dict) -> None:
        _write(tmp_path / ".env", "IOC_TEST_A=from-cwd\n")
        loaded = load_env_file(environ=environ, cwd=tmp_path)
        assert loaded == tmp_path / ".env"
        assert environ["IOC_TEST_A"] == "from-cwd"

    def test_parent_directories_are_not_searched(self, tmp_path: Path, environ: dict) -> None:
        _write(tmp_path / ".env", "IOC_TEST_A=from-parent\n")
        child = tmp_path / "child"
        child.mkdir()
        assert load_env_file(environ=environ, cwd=child) is None
        assert "IOC_TEST_A" not in environ

    def test_no_file_is_fine(self, tmp_path: Path, environ: dict) -> None:
        assert load_env_file(environ=environ, cwd=tmp_path) is None
        assert environ == {}


class TestExplicitPath:
    def test_explicit_path_loaded(self, tmp_path: Path, environ: dict) -> None:
        f = _write(tmp_path / "custom.env", "IOC_TEST_B=explicit\n")
        environ["IOC_ENRICHER_DOTENV"] = str(f)
        assert load_env_file(environ=environ, cwd=tmp_path / "elsewhere") == f
        assert environ["IOC_TEST_B"] == "explicit"

    def test_explicit_path_ignores_cwd_file(self, tmp_path: Path, environ: dict) -> None:
        _write(tmp_path / ".env", "IOC_TEST_C=cwd\n")
        f = _write(tmp_path / "other.env", "IOC_TEST_D=other\n")
        environ["IOC_ENRICHER_DOTENV"] = str(f)
        load_env_file(environ=environ, cwd=tmp_path)
        assert "IOC_TEST_C" not in environ
        assert environ["IOC_TEST_D"] == "other"

    def test_missing_explicit_path_warns_and_loads_nothing(
        self, tmp_path: Path, environ: dict, capsys
    ) -> None:
        environ["IOC_ENRICHER_DOTENV"] = str(tmp_path / "missing.env")
        assert load_env_file(environ=environ, cwd=tmp_path) is None
        err = capsys.readouterr().err
        assert "IOC_ENRICHER_DOTENV" in err
        assert "missing.env" in err


class TestDisabled:
    @pytest.mark.parametrize("value", ["0", "false", "OFF", "none", "no"])
    def test_disabled_values(self, tmp_path: Path, environ: dict, value: str) -> None:
        _write(tmp_path / ".env", "IOC_TEST_E=should-not-load\n")
        environ["IOC_ENRICHER_DOTENV"] = value
        assert load_env_file(environ=environ, cwd=tmp_path) is None
        assert "IOC_TEST_E" not in environ


class TestPrecedence:
    def test_existing_environment_wins(self, tmp_path: Path, environ: dict) -> None:
        _write(tmp_path / ".env", "IOC_TEST_F=from-file\nIOC_TEST_G=only-file\n")
        environ["IOC_TEST_F"] = "from-environment"
        load_env_file(environ=environ, cwd=tmp_path)
        assert environ["IOC_TEST_F"] == "from-environment"
        assert environ["IOC_TEST_G"] == "only-file"

    def test_values_are_not_logged(self, tmp_path: Path, environ: dict, capsys) -> None:
        _write(tmp_path / ".env", "IOC_TEST_SECRET=super-secret-value\n")
        load_env_file(environ=environ, cwd=tmp_path)
        out = capsys.readouterr()
        assert "super-secret-value" not in out.out + out.err


def test_test_suite_runs_hermetically() -> None:
    # The root conftest disables .env loading so a developer's real .env can
    # never leak provider keys (and real API calls) into the test run.
    import os

    assert os.environ.get("IOC_ENRICHER_DOTENV") == "0"


def test_test_suite_writes_no_app_log_file() -> None:
    # LOG_FILE defaults to logs/ioc_enricher.log under the working directory:
    # run from the repository root, the suite appended its records to the
    # real runtime log. Tests log to the console (captured by pytest) only.
    import logging

    from ioc_enricher.utils.logger import get_logger

    get_logger("tests.hermetic").warning("hermetic suite probe")
    handlers = logging.getLogger("ioc_enricher").handlers
    assert not any(isinstance(h, logging.FileHandler) for h in handlers)
