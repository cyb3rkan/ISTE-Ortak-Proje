"""
IOC Enricher web katmanı için FastAPI uygulama fabrikası.

Bu bir *kütüphane* modülüdür — modül seviye ``app = create_app()`` çağrısına
kadar import edilmesi güvenli ve yan etkisizdir. Özel bağımlılıklarla taze bir
app isteyen testler singleton'ı yeniden kullanmak yerine kendileri
``create_app()`` çağırmalıdır.
"""
from __future__ import annotations

import logging
import secrets
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

from ...utils.config import Config
from ...web.settings import WebSettings, load_settings
from .deps import get_settings
from .errors import install_exception_handlers
from .middleware import (
    BodySizeLimitMiddleware,
    RateLimitMiddleware,
    RequestIDMiddleware,
    RequestLoggingMiddleware,
    SecurityHeadersMiddleware,
    build_rate_limiter,
    install_uvicorn_access_scrubber,
)
from .routers import auth, cache, enrich, health, providers, reports
from .security.token_store import build_token_denylist
from .security.user_auth import (
    assert_dev_auth_bypass_allowed,
    log_auth_config_problems,
)

log = logging.getLogger(__name__)


def _docs_enabled(settings: WebSettings) -> bool:
    """
    Decide whether Swagger UI, ReDoc and the OpenAPI schema are served.

    ``enable_docs`` unset means "debug mode only", so a production-like
    deployment never publishes its API surface by default. Authenticated docs
    are not supported, so ``allow_docs_without_auth=False`` keeps them off.
    """
    enabled = settings.debug if settings.enable_docs is None else settings.enable_docs
    if enabled and not settings.allow_docs_without_auth:
        log.warning(
            "docs-disabled: IOC_WEB_ALLOW_DOCS_WITHOUT_AUTH=false and "
            "authenticated docs are not supported, so /docs, /redoc and "
            "/openapi.json are not served."
        )
        return False
    if enabled and not settings.debug:
        log.warning(
            "docs-exposed: /docs, /redoc and /openapi.json are public in a "
            "production-like deployment (IOC_WEB_ENABLE_DOCS=true)."
        )
    return enabled


@asynccontextmanager
async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
    # Runtime directories are created when the server starts, never on import.
    failed = Config.create_directories()
    if failed:
        log.warning(
            "startup: could not create runtime directories (%s); features "
            "that use them will fail until this is fixed.",
            ", ".join(failed),
        )
    yield


def create_app(settings: WebSettings | None = None) -> FastAPI:
    """Build a configured :class:`FastAPI` instance."""
    settings = settings or load_settings()

    # Startup validation. The development-only auth bypass outside debug mode
    # is refused outright. Any other auth problem does not crash the process
    # (health stays reachable) but is logged loudly and fails closed per
    # request — see user_auth.resolve_jwt_config / require_api_key_or_user.
    assert_dev_auth_bypass_allowed(settings)
    log_auth_config_problems(settings)

    docs_enabled = _docs_enabled(settings)
    docs_url = "/docs" if docs_enabled else None
    redoc_url = "/redoc" if docs_enabled else None
    openapi_url = "/openapi.json" if docs_enabled else None

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        docs_url=docs_url,
        redoc_url=redoc_url,
        openapi_url=openapi_url,
        lifespan=_lifespan,
        description=(
            "Threat-intel IOC enrichment API. Tüm istekler framework'ten bağımsız "
            "EnrichmentService üzerinden geçirilir — bkz `ioc_enricher.web.service`."
        ),
    )

    # ------------------------------------------------------------------
    # Middleware (registered in reverse execution order — the last one added
    # is the outermost on the inbound request).
    # ------------------------------------------------------------------

    app.add_middleware(GZipMiddleware, minimum_size=1024)

    # Tarayıcı kullanıcı-auth'u aktifse, frontend httpOnly refresh cookie'yi
    # `credentials: "include"` ile gönderir; bu da `allow_credentials=True`
    # ve açık (wildcard olmayan) bir origin listesi gerektirir — ikincisi
    # settings._env_list tarafından zaten garanti edilir. Sadece API-key auth
    # kullanılıyorsa credentials kapalı kalır, böylece yanlışlıkla bir cookie
    # isteği yetkilendiremez.
    cors_allow_credentials = settings.user_auth_enabled
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_allowed_origins),
        allow_credentials=cors_allow_credentials,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=[
            "Content-Type",
            "X-Request-ID",
            "Authorization",
            "X-CSRF-Token",
        ],
        expose_headers=["X-Request-ID"],
        max_age=600,
    )

    # Rate limiting — only configured when enabled (so unit tests of the
    # business logic can run without tripping limits).
    if settings.rate_limit_enabled:
        # Redis-backed when IOC_WEB_REDIS_URL is set and importable; otherwise
        # a per-process in-memory limiter (see build_rate_limiter).
        limiter = build_rate_limiter(settings.redis_url)
        limiter.configure("enrich", settings.rate_limit_per_minute)
        limiter.configure("enrich_batch", settings.batch_rate_limit_per_minute)
        limiter.configure("clear_cache", settings.clear_cache_per_minute)
        # Auth endpoints: throttle password guessing (and the Argon2 CPU it
        # costs) and refresh-token hammering, per client identity.
        limiter.configure("auth_login", settings.login_rate_limit_per_minute)
        limiter.configure("auth_refresh", settings.refresh_rate_limit_per_minute)
        app.state.rate_limiter = limiter  # exposed for tests
        app.add_middleware(
            RateLimitMiddleware,
            limiter=limiter,
            api_prefix=settings.api_prefix,
            trust_proxy=settings.trust_proxy_headers,
            trusted_proxies=settings.trusted_proxies,
        )

    # One client-IP key for the app's access log and uvicorn's: configured,
    # or random for this app instance (see middleware/logging.py).
    ip_hash_key = settings.access_log_ip_key or secrets.token_hex(32)
    app.add_middleware(RequestLoggingMiddleware, ip_hash_key=ip_hash_key)
    install_uvicorn_access_scrubber(ip_hash_key)
    app.add_middleware(
        SecurityHeadersMiddleware,
        hsts_enabled=settings.hsts_enabled,
        hsts_max_age=settings.hsts_max_age,
    )
    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(
        BodySizeLimitMiddleware, max_body_bytes=settings.max_request_body_bytes
    )

    # ------------------------------------------------------------------
    # Routers
    # ------------------------------------------------------------------
    app.include_router(health.router, prefix=settings.api_prefix)
    app.include_router(auth.router, prefix=settings.api_prefix)
    app.include_router(enrich.router, prefix=settings.api_prefix)
    app.include_router(providers.router, prefix=settings.api_prefix)
    app.include_router(cache.router, prefix=settings.api_prefix)
    app.include_router(reports.router, prefix=settings.api_prefix)

    # ------------------------------------------------------------------
    # Exception handlers (after routers — handlers are registered globally
    # but FastAPI requires the app instance regardless).
    # ------------------------------------------------------------------
    install_exception_handlers(app)

    # Stash settings so test code can introspect.
    app.state.settings = settings

    # Refresh-token revocation store. Redis-backed when IOC_WEB_REDIS_URL is
    # set and the redis package is importable; otherwise a process-local
    # in-memory denylist (see token_store.build_token_denylist).
    app.state.token_denylist = build_token_denylist(settings.redis_url)

    # Bind this concrete settings instance to ``get_settings`` so every
    # dependency (auth policies, etc.) sees the same WebSettings the app was
    # built with — even when the global ``_default_settings`` lru_cache holds
    # a different instance.
    app.dependency_overrides[get_settings] = lambda: settings

    return app


# Module-level instance for ``uvicorn ioc_enricher.web.api.app:app``.
app = create_app()
