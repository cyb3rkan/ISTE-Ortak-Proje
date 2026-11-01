"""
IOC Enricher Agent için web adapter katmanı.

Bu alt-paket, temel :class:`ioc_enricher.IOCEnricher` motorunu HTTP backend
(ör. FastAPI, Flask) için uygun, hafif ve framework'ten bağımsız bir servis
arayüzü ile sarar. Bilerek **kendi başına** FastAPI/Flask/HTTP bağımlılığı
bulundurmaz — amaç, web katmanının çekirdek motoru değiştirmeden sonraki bir
adımda eklenebilmesidir.

Public surface:

- :class:`EnrichmentService`        — isteği uçtan uca orkestre eder.
- :class:`ReportStore`              — UUID anahtarlı rapor kalıcılığı.
- ``schemas`` modülü                — Pydantic istek/yanıt DTO'ları.
- ``mappers`` modülü                — çekirdek ``EnrichmentResult`` → DTO köprüsü.
"""

from .schemas import (
    AIAnalysisDTO,
    BatchEnrichRequest,
    BatchEnrichResponse,
    CacheStatsDTO,
    EnrichmentDTO,
    EnrichRequest,
    MitreTechniqueDTO,
    ProviderResultDTO,
    ProviderStatusDTO,
    ProviderStatusResponse,
    RiskDTO,
)
from .report_store import ReportStore
from .service import (
    EnrichmentExecutionError,
    EnrichmentService,
    ValidationError,
    WebAdapterError,
)

__all__ = [
    # schemas
    "EnrichRequest",
    "BatchEnrichRequest",
    "RiskDTO",
    "ProviderResultDTO",
    "MitreTechniqueDTO",
    "AIAnalysisDTO",
    "EnrichmentDTO",
    "BatchEnrichResponse",
    "ProviderStatusDTO",
    "ProviderStatusResponse",
    "CacheStatsDTO",
    # service / storage
    "EnrichmentService",
    "ReportStore",
    # exceptions
    "WebAdapterError",
    "ValidationError",
    "EnrichmentExecutionError",
]
