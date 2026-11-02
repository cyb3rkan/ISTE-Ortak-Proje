"""
Attach hardening headers to every response.

The CSP is deliberately strict — this is a JSON API, not an HTML app. If
Swagger UI ends up needing a looser policy we will scope the relaxation to
``/docs`` only rather than weakening the global header.

HSTS is opt-in via :class:`WebSettings` (``hsts_enabled``) because dev
environments routinely run over plain HTTP and surfacing HSTS there can
lock browsers into HTTPS for ``localhost`` for up to a year.
"""
from __future__ import annotations

from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}

_API_CSP = (
    "default-src 'self'; "
    "frame-ancestors 'none'; "
    "object-src 'none'; "
    "base-uri 'self'"
)

# Swagger UI loads its assets from a CDN by default. We keep the global CSP
# strict and serve a slightly relaxed one only for the docs pages.
_DOCS_CSP = (
    "default-src 'self'; "
    "img-src 'self' data: https://fastapi.tiangolo.com https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "font-src 'self' https://cdn.jsdelivr.net; "
    "frame-ancestors 'none'; "
    "object-src 'none'; "
    "base-uri 'self'"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        *,
        hsts_enabled: bool = False,
        hsts_max_age: int = 31_536_000,
    ) -> None:
        super().__init__(app)
        self._hsts_enabled = bool(hsts_enabled)
        self._hsts_max_age = max(0, int(hsts_max_age))

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        for k, v in _HEADERS.items():
            response.headers.setdefault(k, v)

        path = request.url.path
        if path in {"/docs", "/redoc"} or path.startswith("/docs/") or path.startswith("/redoc/"):
            response.headers["Content-Security-Policy"] = _DOCS_CSP
        else:
            response.headers.setdefault("Content-Security-Policy", _API_CSP)

        if self._hsts_enabled:
            response.headers.setdefault(
                "Strict-Transport-Security",
                f"max-age={self._hsts_max_age}; includeSubDomains",
            )
        return response
