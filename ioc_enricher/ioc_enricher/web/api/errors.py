"""
RFC 7807 tarzı hata yanıtları ve global istisna işleyicileri.

Tüm işleyiciler :func:`_problem_response` üzerinden yönlendirilir; böylece:

- Stack trace'ler asla istemciye ulaşmaz.
- İç yollar ve traceback'ler :func:`ioc_enricher.web.mappers.sanitize_error_message`
  ile temizlenir.
- ``request_id`` her zaman (middleware tarafından doldurulmuş) yanıt gövdesinde bulunur.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from ...web.mappers import sanitize_error_message
from ...web.service import (
    EnrichmentExecutionError,
    ValidationError as AdapterValidationError,
    WebAdapterError,
)
from .security.auth import (
    AuthError,
    AuthForbiddenError,
    AuthRequiredError,
    AuthUnavailableError,
)

log = logging.getLogger(__name__)


_PROBLEM_MEDIA_TYPE = "application/problem+json"
_BASE_TYPE_URL = "https://errors.ioc-enricher.local"


def _request_id(request: Request) -> Optional[str]:
    return getattr(request.state, "request_id", None)


def _problem_response(
    *,
    request: Request,
    status_code: int,
    title: str,
    detail: str,
    err_type: str,
    extra: Optional[Dict[str, Any]] = None,
) -> JSONResponse:
    safe_detail = sanitize_error_message(detail) or "Bir hata oluştu."
    body: Dict[str, Any] = {
        "type": f"{_BASE_TYPE_URL}/{err_type}",
        "title": title,
        "status": status_code,
        "detail": safe_detail,
        "instance": request.url.path,
        "request_id": _request_id(request),
    }
    if extra:
        # Caller-provided extras are NOT sanitised again — callers must already
        # have produced safe values.
        body.update(extra)
    return JSONResponse(
        status_code=status_code,
        content=body,
        media_type=_PROBLEM_MEDIA_TYPE,
    )


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

async def adapter_validation_handler(
    request: Request, exc: AdapterValidationError
) -> JSONResponse:
    return _problem_response(
        request=request,
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        title="Geçersiz istek",
        detail=str(exc),
        err_type="validation",
    )


async def adapter_execution_handler(
    request: Request, exc: EnrichmentExecutionError
) -> JSONResponse:
    log.warning("enrichment-execution-error rid=%s", _request_id(request))
    return _problem_response(
        request=request,
        status_code=status.HTTP_502_BAD_GATEWAY,
        title="Zenginleştirme başarısız oldu",
        detail=str(exc),
        err_type="enrichment",
    )


async def adapter_generic_handler(
    request: Request, exc: WebAdapterError
) -> JSONResponse:
    log.warning("adapter-error rid=%s", _request_id(request))
    return _problem_response(
        request=request,
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        title="Dahili hata",
        detail=str(exc),
        err_type="adapter",
    )


async def request_validation_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    # Pydantic v2 errors are already safe to surface (no internal paths or
    # secrets), but we still pass everything through sanitize_error_message
    # via _problem_response and we drop the original ``input`` payload — that
    # one *could* echo back attacker-supplied bytes.
    safe_errors = []
    for err in exc.errors():
        safe_errors.append(
            {
                "loc": [str(p) for p in err.get("loc", [])],
                "msg": sanitize_error_message(err.get("msg", "")) or "geçersiz değer",
                "type": err.get("type", "value_error"),
            }
        )
    return _problem_response(
        request=request,
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        title="İstek doğrulaması başarısız",
        detail="Bir veya daha fazla alan doğrulamadan geçemedi.",
        err_type="request-validation",
        extra={"errors": safe_errors},
    )


async def starlette_http_exception_handler(
    request: Request, exc: StarletteHTTPException
) -> JSONResponse:
    detail = exc.detail if isinstance(exc.detail, str) else "HTTP error"
    title_map = {
        400: "Geçersiz istek",
        401: "Yetkisiz",
        403: "Erişim engellendi",
        404: "Bulunamadı",
        405: "İzin verilmeyen yöntem",
        409: "Çakışma",
        413: "İleti çok büyük",
        415: "Desteklenmeyen içerik türü",
        422: "İşlenemeyen varlık",
        429: "Çok fazla istek",
    }
    title = title_map.get(exc.status_code, "HTTP error")
    return _problem_response(
        request=request,
        status_code=exc.status_code,
        title=title,
        detail=detail,
        err_type=f"http-{exc.status_code}",
    )


async def fallback_handler(request: Request, exc: Exception) -> JSONResponse:
    # Log internally with the real exception type; do not leak it.
    log.exception("unhandled-exception rid=%s", _request_id(request))
    return _problem_response(
        request=request,
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        title="Sunucu hatası",
        detail="Beklenmeyen bir hata oluştu. Lütfen daha sonra tekrar deneyin.",
        err_type="internal",
    )


async def auth_error_handler(request: Request, exc: AuthError) -> JSONResponse:
    """
    Render :class:`AuthError` (and its subclasses) as RFC 7807 problem JSON.

    On 401 we include a ``WWW-Authenticate`` header pointing at the configured
    header name (looked up from app state so we never reach back into env at
    response time).
    """
    headers = None
    if isinstance(exc, AuthRequiredError):
        # RFC 7235 wants a WWW-Authenticate header for 401 responses. The API
        # uses a custom header, so we advertise the scheme name only.
        settings = getattr(request.app.state, "settings", None)
        header_name = (
            getattr(settings, "api_key_header_name", "X-API-Key")
            if settings is not None
            else "X-API-Key"
        )
        headers = {"WWW-Authenticate": f'ApiKey header="{header_name}"'}

    response = _problem_response(
        request=request,
        status_code=exc.status_code,
        title=exc.title,
        detail=exc.detail,
        err_type=exc.err_type,
    )
    if headers:
        for k, v in headers.items():
            response.headers[k] = v
    return response


def install_exception_handlers(app: FastAPI) -> None:
    """Wire all custom handlers onto *app*."""
    # Auth handlers — must be registered for the concrete subclasses so
    # FastAPI picks them up before the generic WebAdapterError handler.
    app.add_exception_handler(AuthRequiredError, auth_error_handler)
    app.add_exception_handler(AuthForbiddenError, auth_error_handler)
    app.add_exception_handler(AuthUnavailableError, auth_error_handler)
    app.add_exception_handler(AuthError, auth_error_handler)
    app.add_exception_handler(AdapterValidationError, adapter_validation_handler)
    app.add_exception_handler(EnrichmentExecutionError, adapter_execution_handler)
    app.add_exception_handler(WebAdapterError, adapter_generic_handler)
    app.add_exception_handler(RequestValidationError, request_validation_handler)
    app.add_exception_handler(StarletteHTTPException, starlette_http_exception_handler)
    app.add_exception_handler(Exception, fallback_handler)
