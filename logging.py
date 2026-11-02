"""
Structured JSON access log for every request.

Each request produces one JSON line with these fields and nothing else:

    timestamp     — ISO-8601 UTC.
    level         — log level name.
    event         — always ``http_request``.
    request_id    — correlation id from RequestIDMiddleware.
    method        — HTTP method.
    path          — request path (no query string; UUIDs such as report ids
                    are cut to their first 8 hex digits — a report id is an
                    access token).
    query         — redacted query string (secret-shaped params -> ``***``).
    status_code   — HTTP response status.
    latency_ms    — wall time in milliseconds.
    client_ip_hash — short keyed (HMAC) pseudonym of the client IP.

What we intentionally do NOT log:
    * Request body (may contain user-supplied IOCs).
    * Authorization / API-key / admin-API-key / cookie headers.
    * Any inbound header value other than the request id.
    * Raw client IP (only a keyed, truncated hash is emitted).
    * Raw query parameter values that look like secrets.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import secrets
import time
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import parse_qsl, urlencode

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

log = logging.getLogger("ioc_enricher.web.access")

_SENSITIVE_QS_RE = re.compile(
    r"(?i)(api[_\-]?key|apikey|token|secret|password|authorization)"
)

# Client IPs are logged as an HMAC pseudonym. The IP space is small enough to
# brute-force any unkeyed or published-salt digest, so the key is secret:
# IOC_WEB_ACCESS_LOG_IP_KEY when configured (stable across restarts and
# workers), otherwise random per app instance and never stored (stable for
# correlation within one process only).


_UUID_IN_PATH = re.compile(
    r"\b([0-9a-fA-F]{8})-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)


def _redacted_path(path: str) -> str:
    return _UUID_IN_PATH.sub(r"\1…", path)


def _redacted_query(raw: str) -> str:
    if not raw:
        return ""
    try:
        pairs = parse_qsl(raw, keep_blank_values=True, strict_parsing=False)
    except ValueError:
        return "***"
    safe = [(k, "***" if _SENSITIVE_QS_RE.search(k or "") else v) for k, v in pairs]
    return urlencode(safe)


def _client_ip_hash(request: Request, key: bytes) -> str:
    client = request.client
    host = client.host if client else "unknown"
    digest = hmac.new(key, host.encode("utf-8", "replace"), hashlib.sha256)
    return digest.hexdigest()[:16]


class JsonLogFormatter(logging.Formatter):
    """
    Render log records as single-line JSON.

    Records carrying a ``structured`` dict in ``record.__dict__`` emit that
    dict verbatim (plus timestamp/level). Plain records fall back to a minimal
    ``{timestamp, level, logger, message}`` shape so non-access logs are still
    machine-readable.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "level": record.levelname,
        }
        structured = getattr(record, "structured", None)
        if isinstance(structured, dict):
            payload.update(structured)
        else:
            payload["logger"] = record.name
            payload["message"] = record.getMessage()
        return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, ip_hash_key: Optional[str] = None) -> None:
        super().__init__(app)
        self._ip_key = ip_hash_key.encode("utf-8") if ip_hash_key else secrets.token_bytes(32)

    async def dispatch(self, request: Request, call_next):
        start = time.monotonic()
        status_code = 500
        try:
            response: Response = await call_next(request)
            status_code = response.status_code
            return response
        finally:
            latency_ms = (time.monotonic() - start) * 1000.0
            path = _redacted_path(request.url.path)
            entry = {
                "event": "http_request",
                "request_id": getattr(request.state, "request_id", None),
                "method": request.method,
                "path": path,
                "query": _redacted_query(request.url.query),
                "status_code": status_code,
                "latency_ms": round(latency_ms, 1),
                "client_ip_hash": _client_ip_hash(request, self._ip_key),
            }
            # The message is kept human-readable for plain-text handlers; the
            # JSON handler reads the ``structured`` extra instead.
            log.info(
                "http_request %s %s -> %s",
                request.method,
                path,
                status_code,
                extra={"structured": entry},
            )


# ---------------------------------------------------------------------------
# uvicorn's own access log
# ---------------------------------------------------------------------------

_UVICORN_ACCESS_LOGGER = "uvicorn.access"


class UvicornAccessLogScrubber(logging.Filter):
    """
    uvicorn logs every request itself (``'%s - "%s %s HTTP/%s" %d'``) with the
    raw client address and the full path and query — report ids in paths are
    access tokens. This filter rewrites those arguments the way the app's own
    access log does (client as its keyed pseudonym, UUIDs cut to 8 hex
    digits, secret-shaped query values masked) and keeps uvicorn's format.
    """

    def __init__(self, ip_hash_key: str) -> None:
        super().__init__()
        self._key = ip_hash_key.encode("utf-8")

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: D401
        args = record.args
        if isinstance(args, tuple) and len(args) == 5:
            client, method, target, version, status = args
            record.args = (self._client(client), method, self._target(target), version, status)
        return True

    def _client(self, client_addr: object) -> str:
        text = str(client_addr or "")
        host = text.rsplit(":", 1)[0] if ":" in text else text   # "<host>:<port>"
        if not host:
            return "-"
        return hmac.new(self._key, host.encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:16]

    @staticmethod
    def _target(target: object) -> str:
        path, sep, query = str(target).partition("?")
        return f"{_redacted_path(path)}?{_redacted_query(query)}" if sep else _redacted_path(path)


def install_uvicorn_access_scrubber(ip_hash_key: str) -> None:
    """Attach one scrubber to uvicorn's access logger, replacing an earlier one."""
    access_logger = logging.getLogger(_UVICORN_ACCESS_LOGGER)
    for existing in [f for f in access_logger.filters if isinstance(f, UvicornAccessLogScrubber)]:
        access_logger.removeFilter(existing)
    access_logger.addFilter(UvicornAccessLogScrubber(ip_hash_key))
