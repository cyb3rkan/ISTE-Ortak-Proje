"""
Tests for the structured JSON access log (Phase 5.0.3).

We assert two things:

* The access log emits a structured record with the documented fields.
* No request body, header value, API key, JWT, password, or raw client IP
  ever appears in a log line.
"""
from __future__ import annotations

import json
import logging

from ioc_enricher.web.api.middleware.logging import JsonLogFormatter

from .conftest import build_client


def test_access_log_has_structured_fields(fake_service, caplog) -> None:
    client = build_client(fake_service)
    caplog.set_level(logging.INFO, logger="ioc_enricher.web.access")
    client.get("/api/v1/health")

    records = [
        r for r in caplog.records
        if getattr(r, "structured", None) is not None
    ]
    assert records, "expected at least one structured access-log record"
    entry = records[-1].structured
    for field in (
        "event",
        "request_id",
        "method",
        "path",
        "query",
        "status_code",
        "latency_ms",
        "client_ip_hash",
    ):
        assert field in entry, f"missing field: {field}"
    assert entry["event"] == "http_request"
    assert entry["method"] == "GET"
    assert entry["path"] == "/api/v1/health"


def test_json_formatter_emits_valid_json() -> None:
    formatter = JsonLogFormatter()
    record = logging.LogRecord(
        name="ioc_enricher.web.access",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="http_request",
        args=(),
        exc_info=None,
    )
    record.structured = {
        "event": "http_request",
        "method": "GET",
        "path": "/api/v1/health",
        "status_code": 200,
    }
    line = formatter.format(record)
    parsed = json.loads(line)
    assert parsed["event"] == "http_request"
    assert parsed["status_code"] == 200
    assert "timestamp" in parsed and "level" in parsed


def test_request_body_not_logged(fake_service, caplog) -> None:
    client = build_client(fake_service)
    caplog.set_level(logging.DEBUG, logger="ioc_enricher")
    # An IOC value that we can search for in the logs.
    marker = "203.0.113.77"
    client.post("/api/v1/enrich", json={"ioc": marker})
    for record in caplog.records:
        assert marker not in record.getMessage()
        structured = getattr(record, "structured", None)
        if structured is not None:
            assert marker not in json.dumps(structured)


def test_headers_and_secrets_not_logged(fake_service, caplog) -> None:
    client = build_client(fake_service)
    caplog.set_level(logging.DEBUG, logger="ioc_enricher")
    secret_header = "SECRET-API-KEY-LEAKDETECT-9999"
    secret_token = "Bearer JWT-LEAKDETECT-TOKEN-VALUE"
    client.get(
        "/api/v1/health",
        headers={
            "X-API-Key": secret_header,
            "Authorization": secret_token,
            "Cookie": "ioc_refresh_token=COOKIE-LEAKDETECT",
        },
    )
    for record in caplog.records:
        msg = record.getMessage()
        assert secret_header not in msg
        assert "JWT-LEAKDETECT" not in msg
        assert "COOKIE-LEAKDETECT" not in msg
        structured = getattr(record, "structured", None)
        if structured is not None:
            dumped = json.dumps(structured)
            assert secret_header not in dumped
            assert "COOKIE-LEAKDETECT" not in dumped


def test_query_secrets_redacted(fake_service, caplog) -> None:
    client = build_client(fake_service)
    caplog.set_level(logging.INFO, logger="ioc_enricher.web.access")
    client.get("/api/v1/health?api_key=SHOULD-BE-REDACTED&page=2")
    records = [
        r for r in caplog.records
        if getattr(r, "structured", None) is not None
    ]
    assert records
    query = records[-1].structured["query"]
    assert "SHOULD-BE-REDACTED" not in query
    assert "page=2" in query


def test_client_ip_is_hashed_not_raw(fake_service, caplog) -> None:
    client = build_client(fake_service)
    caplog.set_level(logging.INFO, logger="ioc_enricher.web.access")
    client.get("/api/v1/health")
    records = [
        r for r in caplog.records
        if getattr(r, "structured", None) is not None
    ]
    assert records
    ip_hash = records[-1].structured["client_ip_hash"]
    # TestClient uses 'testclient' as the peer host; the hash must not be it.
    assert ip_hash != "testclient"
    assert len(ip_hash) == 16


def test_access_log_does_not_carry_full_report_ids(fake_service, caplog) -> None:
    # A report id is an access token: the access log keeps a prefix only.
    client = build_client(fake_service)
    caplog.set_level(logging.INFO, logger="ioc_enricher.web.access")
    report_id = "0f8fad5b-d9cb-469f-a165-70867728950e"
    client.get(f"/api/v1/reports/{report_id}")
    records = [r for r in caplog.records if getattr(r, "structured", None) is not None]
    assert records
    path = records[-1].structured["path"]
    assert report_id not in path and report_id not in caplog.text
    assert path.startswith("/api/v1/reports/0f8fad5b")


# ---------------------------------------------------------------------------
# Client IP pseudonym: keyed, not a digest with a published salt
# ---------------------------------------------------------------------------

def _app_client(fake_service, **settings):
    from fastapi.testclient import TestClient

    from ioc_enricher.web.api.app import create_app
    from ioc_enricher.web.api.deps import get_enrichment_service
    from ioc_enricher.web.settings import WebSettings

    app = create_app(WebSettings(rate_limit_enabled=False, **settings))
    app.dependency_overrides[get_enrichment_service] = lambda: fake_service
    return TestClient(app, raise_server_exceptions=False)


def _ip_hash(client, caplog) -> str:
    caplog.clear()
    caplog.set_level(logging.INFO, logger="ioc_enricher.web.access")
    client.get("/api/v1/health")
    records = [r for r in caplog.records if getattr(r, "structured", None) is not None]
    return records[-1].structured["client_ip_hash"]


def test_ip_hash_is_not_the_digest_with_the_old_published_salt(fake_service, caplog) -> None:
    import hashlib

    published = hashlib.sha256(b"ioc-enricher-access-log-v1" + b"testclient").hexdigest()[:16]
    assert _ip_hash(build_client(fake_service), caplog) != published


def test_ip_hash_is_stable_within_one_app(fake_service, caplog) -> None:
    client = build_client(fake_service)
    first = _ip_hash(client, caplog)
    assert first == _ip_hash(client, caplog)
    assert len(first) == 16


def test_without_a_configured_key_every_start_uses_a_fresh_key(fake_service, caplog) -> None:
    # Nothing to brute-force offline: the key is random and never stored.
    assert _ip_hash(build_client(fake_service), caplog) != _ip_hash(build_client(fake_service), caplog)


def test_a_configured_key_keeps_the_pseudonym_across_restarts(fake_service, caplog) -> None:
    import secrets

    key = secrets.token_hex(32)
    first = _ip_hash(_app_client(fake_service, access_log_ip_key=key), caplog)
    assert first == _ip_hash(_app_client(fake_service, access_log_ip_key=key), caplog)
    assert key not in caplog.text


def test_the_key_is_read_from_the_environment_and_never_shown(monkeypatch) -> None:
    import secrets

    from ioc_enricher.web.settings import load_settings

    key = secrets.token_hex(32)
    monkeypatch.setenv("IOC_WEB_ACCESS_LOG_IP_KEY", f"  {key}  ")
    settings = load_settings()
    assert settings.access_log_ip_key == key
    assert key not in repr(settings)


# ---------------------------------------------------------------------------
# uvicorn's own access log line
# ---------------------------------------------------------------------------

_REPORT_ID = "0f8fad5b-d9cb-469f-a165-70867728950e"


def _uvicorn_access_record(caplog):
    caplog.clear()
    with caplog.at_level(logging.INFO, logger="uvicorn.access"):
        logging.getLogger("uvicorn.access").info(
            '%s - "%s %s HTTP/%s" %d', "198.51.100.23:51234", "GET",
            f"/api/v1/reports/{_REPORT_ID}?api_key=FAKE-KEY-VALUE&page=2", "1.1", 200,
        )
    [record] = [r for r in caplog.records if r.name == "uvicorn.access"]
    return record


def test_uvicorn_access_line_is_scrubbed_and_keeps_its_format(fake_service, caplog) -> None:
    # uvicorn logs the raw client address and the full path with query —
    # report ids are access tokens. The app scrubs the arguments the way its
    # own access log does and leaves uvicorn's format intact.
    from uvicorn.logging import AccessFormatter

    _app_client(fake_service)
    record = _uvicorn_access_record(caplog)
    assert len(record.args) == 5          # AccessFormatter reads them by position
    line = AccessFormatter(fmt='%(client_addr)s - "%(request_line)s" %(status_code)s',
                           use_colors=False).format(record)
    for leaked in ("198.51.100.23", _REPORT_ID, "FAKE-KEY-VALUE"):
        assert leaked not in line
    assert "GET /api/v1/reports/0f8fad5b" in line and "page=2" in line and "200" in line


def test_uvicorn_client_pseudonym_matches_the_app_access_log_key(fake_service, caplog) -> None:
    import hashlib
    import hmac
    import secrets

    key = secrets.token_hex(32)
    _app_client(fake_service, access_log_ip_key=key)
    record = _uvicorn_access_record(caplog)
    expected = hmac.new(key.encode(), b"198.51.100.23", hashlib.sha256).hexdigest()[:16]
    assert record.args[0] == expected


def test_creating_apps_repeatedly_does_not_stack_scrubbers(fake_service) -> None:
    _app_client(fake_service)
    _app_client(fake_service)
    scrubbers = [f for f in logging.getLogger("uvicorn.access").filters
                 if type(f).__name__ == "UvicornAccessLogScrubber"]
    assert len(scrubbers) == 1
