"""
Structured logger factory for the IOC Enricher.

Features:
    - One sanitising policy for every record of an ``ioc_enricher`` logger,
      applied when the record is created, so every handler (console, file,
      a host application's root handlers) receives the same safe text: API
      keys, tokens, JWTs, e-mail addresses and URL query strings/credentials
      are masked, and an exception's traceback is sanitised the same way.
    - IOCs are logged as a keyed fingerprint (``ioc_ref``), never as values.
    - Size-bounded rotating file log (LOG_MAX_BYTES x LOG_BACKUP_COUNT,
      UTF-8) that is created by the first record: importing writes nothing.
    - ANSI colour on an interactive console only, and never with NO_COLOR.
    - Centralised log format for easy SIEM ingestion

Usage:
    from ioc_enricher.utils.logger import get_logger, ioc_ref

    log = get_logger(__name__)
    log.info("Enriching %s", ioc_ref(value, "ipv4"))
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import secrets
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Optional, TextIO, Union

from .config import Config

_APP_LOGGER = "ioc_enricher"

# ---------------------------------------------------------------------------
# Sensitive-value scrubbing
# ---------------------------------------------------------------------------

# "<secret-name>=<value>" / "<secret-name>: <value>". The separator is
# required, so prose such as "neither API-key nor ..." is left alone.
_SECRET_PATTERNS = re.compile(
    r"\b((?:groq|openai)[_\-]?api[_\-]?key|x\-apikey|api[_\-]?key|apikey|"
    r"access[_\-]?token|refresh[_\-]?token|token|secret|password|passwd|"
    r"authorization|key)\s*[=:]\s*[^\s,;&]+",
    re.IGNORECASE,
)
_AUTH_SCHEME = re.compile(r"\b(bearer|basic)\s+[A-Za-z0-9._~+/=\-]+", re.IGNORECASE)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*")
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+")
# URL credentials, query string and fragment; the scheme, host and path stay
# readable (an endpoint is not a secret, a token in a query string is).
_URL_USERINFO = re.compile(r"\b((?:https?|ftp)://)[^\s/@'\"<>]+@", re.IGNORECASE)
_URL_QUERY = re.compile(r"\b((?:https?|ftp)://[^\s?#'\"<>]*)\?[^\s'\"<>]*", re.IGNORECASE)
_URL_FRAGMENT = re.compile(r"\b((?:https?|ftp)://[^\s#'\"<>]*)#[^\s'\"<>]*", re.IGNORECASE)

_REDACTED = r"\1=***REDACTED***"


def sanitise_text(text: str) -> str:
    """Mask secrets, tokens, e-mail addresses and URL queries in *text*."""
    text = _URL_USERINFO.sub(r"\1<redacted>@", text)
    text = _URL_QUERY.sub(r"\1?<redacted>", text)
    text = _URL_FRAGMENT.sub(r"\1", text)
    text = _AUTH_SCHEME.sub(_REDACTED, text)
    text = _SECRET_PATTERNS.sub(_REDACTED, text)
    text = _JWT.sub("<token>", text)
    return _EMAIL.sub("<email>", text)


_TRACEBACK_FORMATTER = logging.Formatter()


def _sanitise_record(record: logging.LogRecord, redact_paths: bool = False) -> None:
    """Replace the message, arguments and traceback with sanitised text."""
    try:
        message = record.getMessage()
    except Exception:  # noqa: BLE001 - a bad format string must not break the caller
        message = str(record.msg)
    if redact_paths:
        message = _REQUEST_TARGET.sub("/<redacted>", message)
    record.msg = sanitise_text(message)
    record.args = None
    if record.exc_info:
        record.exc_text = sanitise_text(_TRACEBACK_FORMATTER.formatException(record.exc_info))
        record.exc_info = None
    elif record.exc_text:
        record.exc_text = sanitise_text(record.exc_text)
    if record.stack_info:
        record.stack_info = sanitise_text(record.stack_info)


class _ScrubFilter(logging.Filter):
    """Sanitise a record in place (the same policy as every app record)."""

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: D401
        _sanitise_record(record)
        return True


def _is_app_record(name: object) -> bool:
    # makeLogRecord() and other callers may build records without a name.
    return isinstance(name, str) and (name == _APP_LOGGER or name.startswith(_APP_LOGGER + "."))


# HTTP-client libraries that log the provider request target: urllib3 writes
# "... connection broken by ...: /shodan/host/<ip>?key=<key>" at WARNING when
# it retries. Their records get the app policy plus request paths replaced by
# a placeholder (paths carry IOCs; Shodan's key travels in the query). Other
# libraries are left alone — uvicorn's formatters read their record args.
_HTTP_CLIENT_LOGGERS = ("urllib3", "requests")
# A request path: "/" not part of a scheme ("https://"), host or other path.
_REQUEST_TARGET = re.compile(r"(?<![\w/:.@-])/[^\s'\"<>]*")


def _is_http_client_record(name: object) -> bool:
    return isinstance(name, str) and any(
        name == root or name.startswith(root + ".") for root in _HTTP_CLIENT_LOGGERS
    )


_factory_installed = False


def _install_record_factory() -> None:
    """Sanitise every app record at creation, whichever handler emits it."""
    global _factory_installed  # noqa: PLW0603
    if _factory_installed:
        return
    _factory_installed = True
    previous = logging.getLogRecordFactory()

    def factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
        record = previous(*args, **kwargs)
        if _is_app_record(record.name):
            _sanitise_record(record)
        elif _is_http_client_record(record.name):
            _sanitise_record(record, redact_paths=True)
        return record

    logging.setLogRecordFactory(factory)


# ---------------------------------------------------------------------------
# IOC fingerprints
# ---------------------------------------------------------------------------

# Per-process key, never written anywhere: fingerprints correlate log lines
# about the same IOC within a run, but cannot be reversed with a dictionary
# of likely IOCs (as a plain hash of an IPv4 address could).
_FINGERPRINT_KEY = secrets.token_bytes(32)


def ioc_ref(value: object, ioc_type: Optional[object] = None) -> str:
    """A fixed-length, keyed fingerprint of an IOC, e.g. ``ipv4#3f2a9c1b07de``."""
    digest = hmac.new(
        _FINGERPRINT_KEY, str(value).encode("utf-8", "replace"), hashlib.sha256
    ).hexdigest()[:12]
    label = getattr(ioc_type, "value", ioc_type) or "ioc"
    return f"{label}#{digest}"


# ---------------------------------------------------------------------------
# Log format
# ---------------------------------------------------------------------------

_LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"


# ---------------------------------------------------------------------------
# Colour map for console (ANSI)
# ---------------------------------------------------------------------------

_COLOURS = {
    "DEBUG": "\033[36m",
    "INFO": "\033[32m",
    "WARNING": "\033[33m",
    "ERROR": "\033[31m",
    "CRITICAL": "\033[35m",
    "RESET": "\033[0m",
}


class _ColourFormatter(logging.Formatter):
    """
    Apply ANSI colour codes to the level name. The record is shared by every
    handler, so the coloured level name is restored once formatted.
    """

    def format(self, record: logging.LogRecord) -> str:  # noqa: D401
        original = record.levelname
        record.levelname = f"{_COLOURS.get(original, '')}{original}{_COLOURS['RESET']}"
        try:
            return super().format(record)
        finally:
            record.levelname = original


def wants_colour(stream: Any) -> bool:
    """True for an interactive terminal unless ``NO_COLOR`` is set (no-color.org)."""
    if os.environ.get("NO_COLOR"):
        return False
    isatty = getattr(stream, "isatty", None)
    try:
        return bool(isatty and isatty())
    except (ValueError, OSError):  # closed or detached stream
        return False


def _console_handler(stream: Optional[TextIO] = None) -> logging.Handler:
    """Console handler: colour only for an interactive terminal."""
    stream = stream if stream is not None else sys.stderr
    handler = logging.StreamHandler(stream)
    formatter_cls = _ColourFormatter if wants_colour(stream) else logging.Formatter
    handler.setFormatter(formatter_cls(fmt=_LOG_FORMAT, datefmt=_DATE_FORMAT))
    return handler


class _LazyRotatingFileHandler(RotatingFileHandler):
    """
    Rotating file log that touches the disk only when the first record is
    written: the directory is created then. A location that cannot be
    written disables file logging once, with a short notice (no path).
    """

    def __init__(self, filename: Union[str, Path], max_bytes: int, backup_count: int) -> None:
        super().__init__(
            filename, maxBytes=max_bytes, backupCount=backup_count,
            encoding="utf-8", delay=True,
        )
        self._disabled = False

    def _open(self):  # type: ignore[override]
        Path(self.baseFilename).parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        return super()._open()

    def emit(self, record: logging.LogRecord) -> None:
        if self._disabled:
            return
        if self.stream is None:
            try:
                self.stream = self._open()
            except OSError as exc:
                self._disabled = True
                sys.stderr.write(
                    f"warning: file logging disabled ({type(exc).__name__}); "
                    "console logging continues.\n"
                )
                return
        super().emit(record)


def _file_handler(path: Union[str, Path], max_bytes: int, backup_count: int) -> logging.Handler:
    handler = _LazyRotatingFileHandler(path, max_bytes, backup_count)
    handler.setFormatter(logging.Formatter(fmt=_LOG_FORMAT, datefmt=_DATE_FORMAT))
    return handler


# ---------------------------------------------------------------------------
# Public factory
# ---------------------------------------------------------------------------

_configured: bool = False


def _configure_root() -> None:
    """Configure the root logger once per process (no file is opened yet)."""
    global _configured  # noqa: PLW0603
    if _configured:
        return
    _configured = True

    _install_record_factory()
    root = logging.getLogger(_APP_LOGGER)
    root.setLevel(getattr(logging, Config.LOG_LEVEL, logging.INFO))

    # Console handler
    root.addHandler(_console_handler())

    # File handler (rotating, created by the first record)
    if Config.LOG_FILE:
        root.addHandler(
            _file_handler(Config.LOG_FILE, Config.LOG_MAX_BYTES, Config.LOG_BACKUP_COUNT)
        )

    # Silence noisy third-party loggers
    for noisy in ("urllib3", "requests", "httpx", "openai"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """
    Return a child logger under the ``ioc_enricher`` namespace.

    Args:
        name: Typically ``__name__`` of the calling module.

    Returns:
        A configured :class:`logging.Logger` instance.
    """
    _configure_root()
    if not name.startswith("ioc_enricher"):
        name = f"ioc_enricher.{name}"
    return logging.getLogger(name)
