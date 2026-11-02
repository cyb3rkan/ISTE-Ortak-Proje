"""
Log hygiene and import side effects.

Every record of an ``ioc_enricher`` logger reaches every handler already
sanitised: no IOC values, e-mail addresses, URLs, tokens, API keys or raw
exception text. IOCs are logged as a keyed fingerprint. Colour is for
interactive terminals only and never reaches a file; the file log is
size-bounded and is created by the first record, not by an import.
Importing the package writes nothing to disk.

Only fake IOCs and temporary directories are used.
"""
from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

import ioc_enricher
from ioc_enricher.enricher import IOCEnricher
from ioc_enricher.models import IOCType
from ioc_enricher.providers import VirusTotalProvider
from ioc_enricher.reports.generator import ReportGenerator
from ioc_enricher.utils import logger as app_logging
from ioc_enricher.utils.cache import Cache
from ioc_enricher.utils.config import Config
from ioc_enricher.web.report_store import ReportStore
from ioc_enricher.web.schemas import BatchEnrichRequest
from ioc_enricher.web.service import EnrichmentService

_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl"
_MESSAGE = (
    "lookup failed for analyst@example.com via "
    "https://evil.example.test/path/secret-segment?token=abc123&x=1 "
    f"api_key=SECRET123 bearer {_JWT}"
)
# URL paths stay readable (an endpoint such as an AI base URL is not a
# secret); query strings, fragments and credentials in a URL are masked. IOCs
# are never logged as values in the first place (see TestIocMinimisation).
_MUST_NOT_APPEAR = ["analyst@example.com", "abc123", "SECRET123", _JWT]


def _app_handlers():
    root = logging.getLogger("ioc_enricher")
    files = [h for h in root.handlers if isinstance(h, logging.FileHandler)]
    consoles = [h for h in root.handlers
                if isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler)]
    return consoles, files


def _assert_clean(text: str) -> None:
    for marker in _MUST_NOT_APPEAR:
        assert marker not in text, f"{marker!r} leaked into a log"


# ---------------------------------------------------------------------------
# One sanitising policy for every handler
# ---------------------------------------------------------------------------

class TestSanitisation:

    def test_every_handler_gets_the_same_sanitised_record(self, caplog, tmp_path):
        # The suite runs without the configured file log (LOG_FILE is empty),
        # so the rotating file handler the app attaches is added here.
        root = logging.getLogger("ioc_enricher")
        file_handler = app_logging._file_handler(tmp_path / "app.log", 1024 * 1024, 1)
        root.addHandler(file_handler)
        consoles, files = _app_handlers()
        assert consoles and files
        swapped = []
        buffers = []
        for handler in consoles + files:
            buf = io.StringIO()
            swapped.append((handler, handler.setStream(buf)))
            buffers.append(buf)
        try:
            # A web-style logger created without get_logger() on purpose.
            log = logging.getLogger("ioc_enricher.phase7.hygiene")
            with caplog.at_level(logging.INFO, logger="ioc_enricher"):
                try:
                    raise RuntimeError("upstream said api_key=SECRET123 to analyst@example.com")
                except RuntimeError:
                    log.warning(_MESSAGE, exc_info=True)
        finally:
            for handler, old in swapped:
                handler.setStream(old)
            root.removeHandler(file_handler)
            file_handler.close()
        outputs = [buf.getvalue() for buf in buffers] + [caplog.text]
        for text in outputs:
            assert "lookup failed" in text
            _assert_clean(text)

    @pytest.mark.parametrize("text, expected", [
        ("api_key=SECRET123", "api_key=***REDACTED***"),
        ("contact analyst@example.com now", "contact <email> now"),
        ("see https://evil.example.test/a?b=c#frag for details",
         "see https://evil.example.test/a?<redacted> for details"),
        ("fetch https://user:pa55@host.test/x", "fetch https://<redacted>@host.test/x"),
        ("base_url=https://api.groq.com/openai/v1", "base_url=https://api.groq.com/openai/v1"),
        ("neither API-key nor user auth", "neither API-key nor user auth"),
        (f"bearer {_JWT}", "bearer=***REDACTED***"),
        (f"jwt {_JWT} seen", "jwt <token> seen"),
        ("plain text stays", "plain text stays"),
    ])
    def test_sanitise_text(self, text, expected):
        assert app_logging.sanitise_text(text) == expected

    def test_colour_formatter_does_not_leak_into_other_handlers(self):
        coloured = logging.StreamHandler(io.StringIO())
        coloured.setFormatter(app_logging._ColourFormatter(fmt=app_logging._LOG_FORMAT))
        plain_buf = io.StringIO()
        plain = logging.StreamHandler(plain_buf)
        plain.setFormatter(logging.Formatter(app_logging._LOG_FORMAT))
        log = logging.getLogger("phase7.colour")
        log.propagate = False
        log.handlers = [coloured, plain]
        log.warning("hello")
        assert "\x1b[" in coloured.stream.getvalue()
        assert "\x1b[" not in plain_buf.getvalue()


_FAKE_SHODAN_KEY = "FAKE-SHODAN-KEY-" + "q7Zp"
_REQUEST_TARGET = "/shodan/host/203.0.113.7?key=" + _FAKE_SHODAN_KEY


class TestThirdPartyLoggers:
    """
    urllib3 logs the request target when it retries ("... connection broken
    by ...: /shodan/host/<ip>?key=<key>") at WARNING, which reaches stderr or
    container logs through logging's last-resort handler. The path carries
    the IOC and Shodan's key travels in the query. Other libraries' records
    keep their arguments (uvicorn's formatters read them).
    """

    @staticmethod
    def _records(caplog, name, level, *args):
        app_logging.get_logger("phase11.thirdparty")       # record factory installed
        caplog.clear()
        with caplog.at_level(logging.DEBUG, logger=name):
            logging.getLogger(name).log(level, *args)
        return [r for r in caplog.records if r.name == name]

    def test_urllib3_retry_warning_carries_neither_key_nor_ioc(self, caplog):
        [record] = self._records(
            caplog, "urllib3.connectionpool", logging.WARNING,
            "Retrying (%r) after connection broken by '%r': %s",
            "Retry(total=1, connect=None, read=0)", "NewConnectionError('refused')", _REQUEST_TARGET,
        )
        message = record.getMessage()
        assert "Retrying" in message and "NewConnectionError" in message
        assert _FAKE_SHODAN_KEY not in message
        assert "203.0.113.7" not in message

    def test_urllib3_request_line_keeps_the_host_and_hides_the_target(self, caplog):
        [record] = self._records(
            caplog, "urllib3.connectionpool", logging.DEBUG,
            '%s://%s:%s "%s %s %s" %s %s',
            "https", "api.shodan.io", 443, "GET", _REQUEST_TARGET, "HTTP/1.1", 200, None,
        )
        message = record.getMessage()
        assert message.startswith("https://api.shodan.io:443")
        assert _FAKE_SHODAN_KEY not in message and "203.0.113.7" not in message

    def test_other_third_party_records_are_untouched(self, caplog):
        [record] = self._records(caplog, "uvicorn.error", logging.INFO,
                                 "Started server process [%d]", 4242)
        assert record.args == (4242,)
        assert record.getMessage() == "Started server process [4242]"


class _Tty(io.StringIO):
    def isatty(self) -> bool:
        return True


class TestHandlers:

    @pytest.mark.parametrize("stream_cls, no_color, coloured", [
        pytest.param(io.StringIO, None, False, id="pipe"),
        pytest.param(_Tty, None, True, id="terminal"),
        pytest.param(_Tty, "1", False, id="terminal-NO_COLOR"),
    ])
    def test_console_colour_only_on_an_interactive_terminal(
        self, monkeypatch, stream_cls, no_color, coloured
    ):
        if no_color is None:
            monkeypatch.delenv("NO_COLOR", raising=False)
        else:
            monkeypatch.setenv("NO_COLOR", no_color)
        stream = stream_cls()
        handler = app_logging._console_handler(stream)
        handler.handle(logging.makeLogRecord(
            {"name": "ioc_enricher.t", "levelno": logging.WARNING,
             "levelname": "WARNING", "msg": "hello"}))
        assert ("\x1b[" in stream.getvalue()) is coloured

    def test_file_log_is_lazy_bounded_and_plain(self, tmp_path):
        path = tmp_path / "nested" / "app.log"
        handler = app_logging._file_handler(path, max_bytes=2048, backup_count=2)
        assert not path.parent.exists()          # nothing on disk before a record
        log = logging.getLogger("phase7.file")
        log.propagate = False
        log.handlers = [handler]
        log.setLevel(logging.INFO)
        for i in range(200):
            log.warning("line %d %s", i, "x" * 50)
        handler.close()
        files = sorted(path.parent.glob("app.log*"))
        assert 1 < len(files) <= 3              # current file + 2 backups
        for f in files:
            data = f.read_bytes()
            assert len(data) <= 2048
            assert b"\x1b[" not in data
            data.decode("utf-8")

    def test_unwritable_log_location_disables_file_logging_quietly(self, tmp_path, capsys):
        blocker = tmp_path / "blocker"
        blocker.write_text("not a directory")
        handler = app_logging._file_handler(blocker / "logs" / "app.log", 1024, 1)
        log = logging.getLogger("phase7.unwritable")
        log.propagate = False
        log.handlers = [handler]
        log.warning("first")
        log.warning("second")
        handler.close()
        err = capsys.readouterr().err
        assert err.count("file logging disabled") == 1
        assert str(tmp_path) not in err and "blocker" not in err

    def test_rotation_settings_are_configurable_and_bounded(self, monkeypatch):
        from ioc_enricher.utils.config import _env_int
        assert Config.LOG_MAX_BYTES == 10 * 1024 * 1024
        assert Config.LOG_BACKUP_COUNT == 5
        monkeypatch.setenv("PHASE7_INT", "abc")
        assert _env_int("PHASE7_INT", 5, 0, 20) == 5
        monkeypatch.setenv("PHASE7_INT", "1000")
        assert _env_int("PHASE7_INT", 5, 0, 20) == 20
        monkeypatch.setenv("PHASE7_INT", "-3")
        assert _env_int("PHASE7_INT", 5, 0, 20) == 0


# ---------------------------------------------------------------------------
# IOC minimisation at the call sites
# ---------------------------------------------------------------------------

class _NoProviders(Config):
    VIRUSTOTAL_API_KEY = ""
    ABUSEIPDB_API_KEY = ""
    SHODAN_API_KEY = ""
    OTX_API_KEY = ""
    GREYNOISE_API_KEY = ""
    ZEROBOUNCE_API_KEY = ""


_IOCS = [
    ("203.0.113.7", "203.0.113"),
    ("evil.example.test", "evil.example"),
    ("https://evil.example.test/login?session=abc", "session=abc"),
    ("analyst@example.com", "analyst@"),
]


class TestIocMinimisation:

    def test_fingerprint_is_keyed_fixed_length_and_stable(self):
        ref = app_logging.ioc_ref("203.0.113.7", "ipv4")
        assert ref.startswith("ipv4#") and len(ref) == len("ipv4#") + 12
        assert ref == app_logging.ioc_ref("203.0.113.7", "ipv4")
        assert ref != app_logging.ioc_ref("203.0.113.8", "ipv4")
        assert "203.0.113" not in ref
        # Keyed: not a plain hash anyone could rebuild from a dictionary.
        assert ref[5:] != hashlib.sha256(b"203.0.113.7").hexdigest()[:12]
        assert app_logging.ioc_ref("x").startswith("ioc#")

    def test_enrichment_logs_carry_fingerprints_not_iocs(self, tmp_path, caplog):
        enricher = IOCEnricher(config=_NoProviders,
                               cache=Cache(cache_dir=tmp_path, enabled=True), ai_enabled=False)
        with caplog.at_level(logging.DEBUG, logger="ioc_enricher"):
            for value, _ in _IOCS:
                enricher.enrich(value)
                enricher.enrich(value)          # second time: cache hit path
            enricher.enrich_batch(["203.0.113.8", "not-an-ioc <x>"])
        for value, fragment in _IOCS:
            assert value not in caplog.text and fragment not in caplog.text
        assert "203.0.113.8" not in caplog.text and "not-an-ioc" not in caplog.text
        assert "ipv4#" in caplog.text

    def test_provider_request_log_has_no_ioc(self, caplog):
        provider = VirusTotalProvider(api_key="k", timeout=5, rate_limiter=MagicMock(
            wait=MagicMock(return_value=True)))
        resp = MagicMock(status_code=404, headers={})
        provider._session.request = MagicMock(return_value=resp)
        with caplog.at_level(logging.DEBUG, logger="ioc_enricher"):
            provider.lookup_ip("203.0.113.9")
        assert "203.0.113.9" not in caplog.text
        assert "ip_addresses" not in caplog.text

    def test_batch_failure_log_has_no_ioc_or_exception_text(self, tmp_path, caplog):
        class _Odd:
            @property
            def ioc_type(self):
                raise RuntimeError("upstream detail for 203.0.113.7")

        class _Enricher:
            def enrich(self, raw_ioc, save_report=None, use_cache=True):
                return _Odd()

        service = EnrichmentService(enricher=_Enricher(), report_store=ReportStore(base_dir=tmp_path))
        with caplog.at_level(logging.DEBUG, logger="ioc_enricher"):
            response = service.enrich_batch(BatchEnrichRequest(iocs=["203.0.113.7"]))
        assert response.summary["failed"] == 1
        assert "203.0.113.7" not in caplog.text
        assert "upstream detail" not in caplog.text
        assert "RuntimeError" in caplog.text

    def test_saved_report_log_has_no_path_or_ioc(self, tmp_path, monkeypatch, caplog):
        for cls in _config_classes():
            monkeypatch.setattr(cls, "REPORTS_DIR", tmp_path)
        enricher = IOCEnricher(config=_NoProviders,
                               cache=Cache(cache_dir=tmp_path / "c", enabled=False), ai_enabled=False)
        result = enricher.enrich("evil.example.test", use_cache=False)
        with caplog.at_level(logging.DEBUG, logger="ioc_enricher"):
            ReportGenerator().save(result, "json")
        assert "evil.example" not in caplog.text
        assert str(tmp_path) not in caplog.text


# ---------------------------------------------------------------------------
# File-system side effects
# ---------------------------------------------------------------------------

_IMPORT_PROBE = r'''
import builtins, io, json, os, pathlib
writes = []
real_open = builtins.open
def guarded_open(file, mode="r", *args, **kwargs):
    if isinstance(mode, str) and any(flag in mode for flag in "wax+"):
        writes.append(["open", os.path.basename(str(file))])
        return io.BytesIO() if "b" in mode else io.StringIO()
    return real_open(file, mode, *args, **kwargs)
def blocked_mkdir(self, *args, **kwargs):
    writes.append(["mkdir", self.name])
builtins.open = guarded_open
io.open = guarded_open
pathlib.Path.mkdir = blocked_mkdir
os.makedirs = lambda name, *a, **k: writes.append(["makedirs", os.path.basename(str(name))])
os.mkdir = lambda name, *a, **k: writes.append(["mkdir", os.path.basename(str(name))])
import ioc_enricher
import ioc_enricher.enricher
import ioc_enricher.cli.main
import ioc_enricher.web.service
import ioc_enricher.web.report_store
print(json.dumps(writes))
'''


def test_importing_the_package_writes_nothing(tmp_path):
    package_root = Path(ioc_enricher.__file__).resolve().parents[1]
    env = dict(os.environ, PYTHONPATH=str(package_root), IOC_ENRICHER_DOTENV="0",
               PYTHONDONTWRITEBYTECODE="1")
    proc = subprocess.run([sys.executable, "-B", "-c", _IMPORT_PROBE], cwd=tmp_path, env=env,
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert json.loads(proc.stdout.strip().splitlines()[-1]) == []


def _config_classes() -> list:
    """
    Every ``Config`` class object the modules under test hold: some AI tests
    reload the config module, so a module imported later may see a newer
    class than this test module. Patching all of them keeps the test away
    from the real runtime directories whatever the test order.
    """
    import importlib

    classes: list = [Config]
    for name in ("ioc_enricher.utils.config", "ioc_enricher.cli.main",
                 "ioc_enricher.utils.cache", "ioc_enricher.reports.generator",
                 "ioc_enricher.web.api.app"):
        cls = importlib.import_module(name).Config
        if cls not in classes:
            classes.append(cls)
    return classes


def _point_runtime_dirs(monkeypatch, base: Path) -> dict:
    dirs = {"DATA_DIR": base / "data", "CACHE_DIR": base / "data" / "cache",
            "REPORTS_DIR": base / "reports", "LOGS_DIR": base / "logs"}
    for cls in _config_classes():
        for name, path in dirs.items():
            monkeypatch.setattr(cls, name, path)
    return dirs


def test_runtime_directories_are_created_on_request(tmp_path, monkeypatch):
    dirs = _point_runtime_dirs(monkeypatch, tmp_path)
    assert Config.create_directories() == []
    assert all(path.is_dir() for path in dirs.values())


def test_directory_failures_are_reported_without_raising(tmp_path, monkeypatch):
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory")
    _point_runtime_dirs(monkeypatch, tmp_path)
    monkeypatch.setattr(Config, "CACHE_DIR", blocker / "cache")
    assert Config.create_directories() == ["CACHE_DIR"]
    assert (tmp_path / "reports").is_dir()


def test_cli_creates_runtime_directories_at_start(tmp_path, monkeypatch, capsys):
    from ioc_enricher.cli.main import main
    dirs = _point_runtime_dirs(monkeypatch, tmp_path)
    assert main(["--cache-stats", "--no-banner"]) == 0
    assert all(path.is_dir() for path in dirs.values())


def test_web_app_creates_runtime_directories_at_startup_not_on_creation(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from ioc_enricher.web.api.app import create_app
    from ioc_enricher.web.settings import WebSettings
    dirs = _point_runtime_dirs(monkeypatch, tmp_path)
    app = create_app(WebSettings(rate_limit_enabled=False, auth_enabled=True, api_keys=["k" * 32]))
    assert not any(path.exists() for path in dirs.values())
    with TestClient(app):
        assert all(path.is_dir() for path in dirs.values())


_DIRS_PROBE = (
    "import json; from ioc_enricher.utils.config import Config; "
    "print(json.dumps({k: str(getattr(Config, k)) for k in "
    "('DATA_DIR', 'CACHE_DIR', 'REPORTS_DIR')}))"
)


def _config_dirs(tmp_path, **env_overrides) -> dict:
    package_root = Path(ioc_enricher.__file__).resolve().parents[1]
    env = {k: v for k, v in os.environ.items()
           if k not in ("IOC_ENRICHER_DATA_DIR", "IOC_ENRICHER_REPORTS_DIR")}
    env.update(PYTHONPATH=str(package_root), IOC_ENRICHER_DOTENV="0",
               PYTHONDONTWRITEBYTECODE="1", **env_overrides)
    proc = subprocess.run([sys.executable, "-B", "-c", _DIRS_PROBE], cwd=tmp_path, env=env,
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr[-2000:]
    return json.loads(proc.stdout.strip().splitlines()[-1])


def test_runtime_directories_default_to_the_package_base(tmp_path):
    base = Path(ioc_enricher.__file__).resolve().parents[1]
    dirs = _config_dirs(tmp_path)
    assert Path(dirs["DATA_DIR"]) == base / "data"
    assert Path(dirs["CACHE_DIR"]) == base / "data" / "cache"
    assert Path(dirs["REPORTS_DIR"]) == base / "reports"


def test_runtime_directories_can_be_moved_by_the_environment(tmp_path):
    # Containers mount volumes at fixed paths (docker/docker-compose.yml).
    data, reports = tmp_path / "vol-data", tmp_path / "vol-reports"
    dirs = _config_dirs(tmp_path, IOC_ENRICHER_DATA_DIR=f"  {data}  ",
                        IOC_ENRICHER_REPORTS_DIR=str(reports))
    assert Path(dirs["DATA_DIR"]) == data
    assert Path(dirs["CACHE_DIR"]) == data / "cache"
    assert Path(dirs["REPORTS_DIR"]) == reports
    assert not data.exists() and not reports.exists()      # nothing created at import
