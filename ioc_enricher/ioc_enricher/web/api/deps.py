"""
FastAPI dependency providers.

These are intentionally tiny so that ``app.dependency_overrides`` can swap any
of them in tests without monkey-patching. The defaults build a single shared
:class:`EnrichmentService` (which in turn wraps the singleton-ish IOCEnricher
that is expensive to build because it instantiates all configured providers).
"""
from __future__ import annotations

from functools import lru_cache

from ...enricher import IOCEnricher
from ...web.report_store import ReportStore
from ...web.service import EnrichmentService
from ...web.settings import WebSettings, load_settings


@lru_cache(maxsize=1)
def _default_enricher() -> IOCEnricher:
    return IOCEnricher()


@lru_cache(maxsize=1)
def _default_report_store() -> ReportStore:
    return ReportStore()


@lru_cache(maxsize=1)
def _default_service() -> EnrichmentService:
    return EnrichmentService(
        enricher=_default_enricher(),
        report_store=_default_report_store(),
        batch_deadline_seconds=_default_settings().batch_deadline_seconds,
    )


@lru_cache(maxsize=1)
def _default_settings() -> WebSettings:
    return load_settings()


def get_enricher() -> IOCEnricher:
    """Return the process-wide :class:`IOCEnricher` singleton."""
    return _default_enricher()


def get_report_store() -> ReportStore:
    """Return the process-wide :class:`ReportStore` singleton."""
    return _default_report_store()


def get_enrichment_service() -> EnrichmentService:
    """Return the process-wide :class:`EnrichmentService` singleton."""
    return _default_service()


def get_settings() -> WebSettings:
    """Return the cached web settings."""
    return _default_settings()


def reset_dependency_cache() -> None:
    """Test helper — drops all cached singletons."""
    _default_enricher.cache_clear()
    _default_report_store.cache_clear()
    _default_service.cache_clear()
    _default_settings.cache_clear()


__all__ = [
    "get_enricher",
    "get_report_store",
    "get_enrichment_service",
    "get_settings",
    "reset_dependency_cache",
]
