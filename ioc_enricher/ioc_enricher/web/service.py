"""
HTTP katmanının kullanabileceği, framework'ten bağımsız enrichment servisi.

``EnrichmentService``, :class:`ioc_enricher.IOCEnricher` çekirdeğini sarar ve
sadece DTO'lar aracılığıyla (iç dataclass'lar veya provider ham payload'ları
değil) dışarı sunar. FastAPI / Flask / aiohttp gibi herhangi bir web framework'üne
bağımlılığı yoktur — import edilmesi ucuz ve yan etkisiz olmalıdır; böylece
birim testleri ve gelecekteki HTTP rotaları aynı servisi güvenle kullanabilir.
"""
from __future__ import annotations

import dataclasses
import time
import uuid
from typing import Any, Callable, Dict, List, Optional

from pydantic import ValidationError as SchemaValidationError

from ..enricher import IOCEnricher
from ..models.ioc import IOCType
from ..models.result import EnrichmentResult
from ..reports.generator import ReportGenerator
from ..utils.config import Config
from ..utils.logger import get_logger, ioc_ref
from .mappers import safe_provider_summary, sanitize_error_message, to_enrichment_dto
from .report_store import REPORT_SCHEMA_VERSION, ReportStore, ReportStoreError
from .schemas import (
    BatchEnrichRequest,
    BatchEnrichResponse,
    CacheStatsDTO,
    EnrichmentDTO,
    EnrichRequest,
    ProviderStatusDTO,
    ProviderStatusResponse,
)

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Public exception hierarchy
# ---------------------------------------------------------------------------

class WebAdapterError(Exception):
    """Tüm web-adapter istisnalarının ortak üst sınıfı."""


class ValidationError(WebAdapterError):
    """İş mantığı düzeyinde doğrulamayı geçen isteklere özel olmayan hata."""


class EnrichmentExecutionError(WebAdapterError):
    """Altdaki enrichment pipeline'ı beklenmedik şekilde başarısız olduğunda atılır."""


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class EnrichmentService:
    """
    Pydantic DTO'ları ile çekirdek motor arasında çeviri yapan ince orkestratör.

    Args:
        enricher:     Opsiyonel önceden oluşturulmuş :class:`IOCEnricher` (testlerin
                      ağa veya ortam değişkenlerine dokunmadan sahte bir örnek
                      enjekte etmesine izin verir).
        report_store: Opsiyonel :class:`ReportStore` örneği. Varsayılan olarak
                      dosya sistemi tabanlı bir store kullanılır: ``Config.REPORTS_DIR/web``.
    """

    def __init__(
        self,
        enricher: Optional[IOCEnricher] = None,
        report_store: Optional[ReportStore] = None,
        *,
        batch_deadline_seconds: Optional[float] = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._enricher = enricher
        self._report_store = report_store
        # Total time budget for one batch request. ``None``/<=0 disables it
        # (historical behaviour, kept as the constructor default).
        self._batch_deadline_seconds = (
            batch_deadline_seconds
            if batch_deadline_seconds is not None and batch_deadline_seconds > 0
            else None
        )
        self._clock = clock

    # ------------------------------------------------------------------
    # Lazily-created dependencies
    # ------------------------------------------------------------------

    @property
    def enricher(self) -> IOCEnricher:
        if self._enricher is None:
            self._enricher = IOCEnricher()
        return self._enricher

    @property
    def report_store(self) -> ReportStore:
        if self._report_store is None:
            self._report_store = ReportStore()
        return self._report_store

    # ------------------------------------------------------------------
    # Single-IOC enrichment
    # ------------------------------------------------------------------

    def enrich_single(self, request: EnrichRequest) -> EnrichmentDTO:
        """Tek bir IOC'yi zenginleştirir ve web için güvenli bir DTO döner."""
        request_id = uuid.uuid4().hex

        try:
            result = self.enricher.enrich(
                request.ioc,
                save_report=None,  # the web layer handles persistence
                use_cache=request.use_cache,
            )
        except ValueError as exc:
            # Çekirdek validator'dan gelen doğrulama hatası.
            raise ValidationError(sanitize_error_message(str(exc)) or "Geçersiz IOC.") from exc
        except Exception as exc:  # noqa: BLE001
            log.warning("enrich_single failed for request_id=%s", request_id)
            raise EnrichmentExecutionError(
                sanitize_error_message(str(exc)) or "Zenginleştirme başarısız oldu."
            ) from exc

        # Optional ioc_type cross-check ("auto" disables the check).
        self._check_expected_ioc_type(request.ioc_type, result.ioc_type)

        # Optional report persistence via the web-side store (NOT the core
        # one — we want UUID-keyed filenames, not IOC-derived ones).
        report_id: Optional[str] = None
        if request.save_report_format is not None:
            report_id = self._persist_report(
                result_dto_source=result,
                fmt=request.save_report_format,
                request_id=request_id,
            )

        return to_enrichment_dto(result, report_id=report_id, request_id=request_id)

    # ------------------------------------------------------------------
    # Batch enrichment
    # ------------------------------------------------------------------

    def enrich_batch(self, request: BatchEnrichRequest) -> BatchEnrichResponse:
        """
        Enrich up to 50 IOCs. Partial failures are reported per-item; the
        overall response is always returned.

        When a batch deadline is configured, no new IOC is *started* once the
        budget is spent; the remaining IOCs are reported in ``errors`` with
        ``error_type="deadline_exceeded"``. An IOC already in flight is not
        interrupted; its provider phase is bounded by ``IOC_DEADLINE_SECONDS``,
        so the worst case is the budget plus one IOC's deadline (and its
        optional AI step).
        """
        deadline = (
            self._clock() + self._batch_deadline_seconds
            if self._batch_deadline_seconds is not None
            else None
        )
        # Deduplicate while preserving order. Schema-level validation has
        # already trimmed/normalised the strings.
        seen: set[str] = set()
        unique: List[str] = []
        for value in request.iocs:
            if value not in seen:
                seen.add(value)
                unique.append(value)
        duplicates_removed = len(request.iocs) - len(unique)

        results: List[EnrichmentDTO] = []
        errors: List[Dict[str, Any]] = []
        deadline_exceeded = 0

        for value in unique:
            if deadline is not None and self._clock() >= deadline:
                deadline_exceeded += 1
                errors.append({
                    "ioc": value,
                    "error_type": "deadline_exceeded",
                    "message": "Batch süre bütçesi aşıldı; bu IOC işlenmedi.",
                })
                continue
            try:
                sub_req = EnrichRequest(
                    ioc=value,
                    ioc_type=request.ioc_type,
                    use_cache=request.use_cache,
                    save_report_format=request.save_report_format,
                )
                dto = self.enrich_single(sub_req)
                results.append(dto)
            except ValidationError as exc:
                errors.append({
                    "ioc": value,
                    "error_type": "validation_error",
                    "message": sanitize_error_message(str(exc)) or "Geçersiz IOC.",
                })
            except EnrichmentExecutionError as exc:
                errors.append({
                    "ioc": value,
                    "error_type": "execution_error",
                    "message": sanitize_error_message(str(exc)) or "Zenginleştirme başarısız oldu.",
                })
            except Exception as exc:  # noqa: BLE001
                # Defensive: never let one bad IOC nuke the whole batch.
                log.warning("Unexpected batch error for %s (%s)", ioc_ref(value), type(exc).__name__)
                errors.append({
                    "ioc": value,
                    "error_type": "unknown_error",
                    "message": sanitize_error_message(str(exc)) or "Beklenmeyen bir hata.",
                })

        summary = {
            "total": len(request.iocs),
            "unique": len(unique),
            "success": len(results),
            "failed": len(errors),
            "duplicates_removed": duplicates_removed,
            "deadline_exceeded": deadline_exceeded,
        }
        if deadline_exceeded:
            log.warning(
                "batch deadline exceeded: %d of %d IOC(s) skipped",
                deadline_exceeded,
                len(unique),
            )
        return BatchEnrichResponse(results=results, errors=errors, summary=summary)

    # ------------------------------------------------------------------
    # Provider / cache introspection
    # ------------------------------------------------------------------

    def get_provider_status(self) -> ProviderStatusResponse:
        """Provider durumu — API anahtarları veya sırlar asla döndürülmez."""
        try:
            active = self.enricher.provider_status()
        except Exception as exc:  # noqa: BLE001
            log.warning("provider_status failed (%s)", type(exc).__name__)
            active = {}

        cfg_status: Dict[str, bool] = {}
        try:
            cfg_status = dict(Config.provider_status())
        except Exception as exc:  # noqa: BLE001
            log.warning("Config.provider_status failed (%s)", type(exc).__name__)

        providers: List[ProviderStatusDTO] = []
        for name, configured in cfg_status.items():
            enabled = name in active
            providers.append(
                ProviderStatusDTO(
                    name=name,
                    enabled=enabled,
                    configured=bool(configured),
                    status=(
                        "active" if enabled
                        else "configured" if configured
                        else "disabled"
                    ),
                    last_error=None,
                )
            )

        ai_enabled = False
        try:
            ai_enabled = bool(getattr(self.enricher, "_ai", None) and self.enricher._ai.enabled)
        except Exception:  # noqa: BLE001
            ai_enabled = False

        return ProviderStatusResponse(providers=providers, ai_enabled=ai_enabled)

    def get_cache_stats(self) -> CacheStatsDTO:
        """Önbellek istatistiklerini döner; hiçbir IOC değeri açığa çıkarılmaz."""
        try:
            stats = self.enricher._cache.stats()
        except Exception as exc:  # noqa: BLE001
            log.warning("cache stats failed (%s)", type(exc).__name__)
            return CacheStatsDTO(entries=0)

        entries = int(stats.get("entry_count", 0) or 0)
        size_kb = stats.get("total_size_kb")
        size_bytes: Optional[int] = (
            int(round(float(size_kb) * 1024)) if size_kb is not None else None
        )
        ttl_hours = stats.get("ttl_hours")
        return CacheStatsDTO(
            entries=entries,
            size_bytes=size_bytes,
            ttl_hours=float(ttl_hours) if ttl_hours is not None else None,
        )

    def clear_cache(self) -> Dict[str, Any]:
        """
        Disk üzerindeki enrichment önbelleğini temizler.

        Not: Bu PR'de bir authentication katmanı yoktur. Bu metodu expose eden
        gelecekteki HTTP rota kesinlikle admin yetkisi gerektirmelidir.
        """
        try:
            removed = self.enricher._cache.clear()
            return {"cleared": True, "removed_entries": int(removed or 0)}
        except Exception as exc:  # noqa: BLE001
            log.warning("clear_cache failed (%s)", type(exc).__name__)
            return {
                "cleared": False,
                "removed_entries": 0,
                "error": sanitize_error_message(str(exc)) or "Önbellek temizleme başarısız oldu",
            }

    def get_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        """
        Daha önce kaydedilmiş bir raporu döner veya None.

        Stored reports are validated again before they leave the service: the
        envelope must carry the current ``schema``, JSON content must match
        the API's ``EnrichmentDTO`` and passes the provider / meta allow-lists,
        and only allow-listed metadata is returned. A report from before this
        policy, or one that fails the checks, is not served.
        """
        try:
            stored = self.report_store.get_report(report_id)
        except ReportStoreError as exc:
            raise ValidationError(str(exc)) from exc
        if stored is None:
            return None
        return _servable_report(report_id, stored)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _check_expected_ioc_type(expected: Optional[str], detected: IOCType) -> None:
        """
        Çağıran taraf ``ioc_type``'ı belirli bir değere sabitlediyse ("auto" dışında),
        tespit edilen tipin uyumlu olduğunu doğrular. Uyumsuzluk, istemci tarafı
        doğrulama hatasıdır.
        """
        if not expected or expected == "auto":
            return

        # The external "hash" umbrella maps to the three internal hash types.
        if expected == "hash":
            if detected not in IOCType.hash_types():
                raise ValidationError(
                    f"ioc_type=hash but detected type is '{detected.value}'"
                )
            return

        if expected != detected.value:
            raise ValidationError(
                f"ioc_type={expected!r} does not match detected "
                f"type {detected.value!r}"
            )

    def _persist_report(
        self,
        result_dto_source: Any,
        fmt: str,
        request_id: str,
    ) -> Optional[str]:
        """
        Raporu istenen formatta oluşturur ve store'a iletir.

        Kalıcılık başarısız olursa enrichment yanıtını bozmamalıdır — sadece
        ``report_id`` None döner ve çağıran taraf daha sonra yeniden deneyebilir.
        """
        try:
            reporter = ReportGenerator()
            if fmt == "json":
                # The same allow-listed view the API returns — never the raw
                # provider data — so consumers can parse it back.
                content: Any = to_enrichment_dto(
                    result_dto_source, request_id=request_id
                ).model_dump(mode="json")
            elif fmt == "markdown":
                content = reporter.to_markdown(_web_safe(result_dto_source))
            else:  # pragma: no cover - schema validator forbids other values
                return None
            metadata = {
                "request_id": request_id,
                "ioc_type": result_dto_source.ioc_type.value,
            }
            return self.report_store.save_report(
                content=content, format=fmt, metadata=metadata
            )
        except ReportStoreError as exc:
            log.warning("Report persistence failed: %s", exc)
            return None
        except Exception as exc:  # noqa: BLE001
            log.warning("Unexpected report-persistence error (%s)", type(exc).__name__)
            return None


# ---------------------------------------------------------------------------
# Report content policy
# ---------------------------------------------------------------------------

# What a served report may carry besides its content.
_REPORT_METADATA_KEYS = frozenset({"request_id", "ioc_type"})
# The ``meta`` keys ``to_enrichment_dto`` writes.
_REPORT_DTO_META_KEYS = frozenset({"from_cache", "execution_time_ms", "timestamp", "request_id"})


def _web_safe(result: EnrichmentResult) -> EnrichmentResult:
    """
    *result* with provider data cut down to the API allow-list and provider
    errors sanitised, for rendering a report: a report never carries more
    provider detail than the API response.
    """
    safe = {
        name: dataclasses.replace(
            pr,
            data=safe_provider_summary(pr.provider or name, pr.data or {}) or None,
            error=sanitize_error_message(pr.error) if pr.error else None,
        )
        for name, pr in result.provider_results.items()
    }
    return dataclasses.replace(result, provider_results=safe)


def _servable_report(report_id: str, stored: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The stored report re-validated for output, or None when it is not servable."""
    if stored.get("schema") != REPORT_SCHEMA_VERSION:
        log.warning("Report %s… predates the current report policy; not served.", report_id[:8])
        return None
    fmt = stored.get("format")
    content = stored.get("content")
    if fmt == "json":
        try:
            dto = EnrichmentDTO.model_validate(content)
        except SchemaValidationError:
            log.warning("Report %s… does not match the report schema; not served.", report_id[:8])
            return None
        for provider in dto.providers:
            provider.data_summary = safe_provider_summary(provider.name, provider.data_summary)
            provider.error = sanitize_error_message(provider.error) if provider.error else None
        dto.meta = {k: v for k, v in dto.meta.items() if k in _REPORT_DTO_META_KEYS}
        content = dto.model_dump(mode="json")
    elif fmt != "markdown" or not isinstance(content, str):
        log.warning("Report %s… has an unexpected format; not served.", report_id[:8])
        return None
    metadata = stored.get("metadata")
    return {
        "report_id": report_id,
        "format": fmt,
        "created_at": stored.get("created_at"),
        "metadata": {
            k: v for k, v in (metadata if isinstance(metadata, dict) else {}).items()
            if k in _REPORT_METADATA_KEYS
        },
        "content": content,
    }
