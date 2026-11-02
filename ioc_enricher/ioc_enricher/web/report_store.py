"""
Web adapter için UUID anahtarlı rapor kalıcılığı.

Raporlar tek bir iyi bilinen temel dizin altında dosya olarak saklanır. Çağıran
asla dosya adını seçmez: store bir UUID4 ``report_id`` üretir ve bu, sabit
bir uzantı ile birleştirilerek *tek* izin verilen dosya adı olur. Bu, çağıranlar
için path-traversal sınıfı hatalarını ortadan kaldırır.

Bu, kasıtlı olarak dosya sistemi destekli ince bir uygulamadır. Genel metodların
(``save_report`` / ``get_report`` / ``delete_report``) şekli, nihai FastAPI /
veritabanı katmanının tüketeceği biçimdedir — backend'i değiştirmek ileride
sadece bir sınıf değişikliği gerektirir.

Saklama: ``REPORT_RETENTION_DAYS`` günden eski raporlar ve toplam boyut
``REPORT_MAX_TOTAL_MB``'yi aşınca en eski raporlar silinir. Temizlik
``save_report`` içinden en fazla ``PRUNE_INTERVAL_SECONDS``'ta bir çalışır
(import sırasında asla) ve yalnızca bu dizindeki UUID adlı rapor dosyalarına
ve yan dosyalarına dokunur. Yazmalar atomiktir ve dosyalar yalnızca sahibine
açıktır (POSIX). Her rapor ``schema`` sürümü taşır.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from ..utils.config import Config
from ..utils.fileio import TEMP_SUFFIX, atomic_write_text, private_dir
from ..utils.logger import get_logger

log = get_logger(__name__)

#: Version of the stored report envelope (and of what ``content`` holds).
REPORT_SCHEMA_VERSION = 2
#: ``save_report`` prunes the report directory at most this often.
PRUNE_INTERVAL_SECONDS = 3600.0

_ALLOWED_FORMATS: tuple[str, ...] = ("json", "markdown")
_REPORT_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_EXTENSIONS: Dict[str, str] = {"json": ".json", "markdown": ".md"}
_REPORT_FILE_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.(?:json|md)$"
)
_TEMP_FILE_RE = re.compile(
    r"^\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\..+"
    + re.escape(TEMP_SUFFIX) + r"$"
)
_SIDECAR_SUFFIX = ".meta.json"
_STALE_TEMP_SECONDS = 3600.0
_DAY_SECONDS = 86_400


def _short(report_id: str) -> str:
    """Log form of a report id: a report id is an access token, log a prefix."""
    return f"{report_id[:8]}…"


class ReportStoreError(RuntimeError):
    """Report-store operasyonları için temel hata sınıfı."""


class ReportStore:
    """
    Dosya sistemi tabanlı, UUID anahtarlı rapor store'u.

    Args:
        base_dir: Raporların yazıldığı dizin. Varsayılan ``<Config.REPORTS_DIR>/web``.
            Dizin ilk kullanımda oluşturulur.
        retention_days: Saklama süresi (varsayılan ``Config.REPORT_RETENTION_DAYS``; 1–3650).
        max_total_mb: Toplam boyut sınırı (varsayılan ``Config.REPORT_MAX_TOTAL_MB``).
        clock: Duvar saati (testler için enjekte edilebilir).
    """

    def __init__(
        self,
        base_dir: Optional[Union[str, Path]] = None,
        retention_days: Optional[int] = None,
        max_total_mb: Optional[int] = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if base_dir is None:
            base = Path(Config.REPORTS_DIR) / "web"
        else:
            base = Path(base_dir)
        private_dir(base)
        # Resolve so that all later path-traversal checks compare against
        # the *real* path, not a relative one.
        self._base_dir: Path = base.resolve()
        days = Config.REPORT_RETENTION_DAYS if retention_days is None else retention_days
        self._retention_days = min(max(int(days), 1), 3650)
        size_mb = Config.REPORT_MAX_TOTAL_MB if max_total_mb is None else max_total_mb
        self._max_total_mb = min(max(int(size_mb), 1), 100_000)
        self._clock = clock
        self._last_prune: Optional[float] = None
        self._prune_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def base_dir(self) -> Path:
        return self._base_dir

    @property
    def retention_days(self) -> int:
        return self._retention_days

    @property
    def max_total_mb(self) -> int:
        return self._max_total_mb

    def save_report(
        self,
        content: Union[str, Dict[str, Any]],
        format: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Persist *content* in the requested *format* and return its report id.

        Args:
            content:  String (markdown) or JSON-serialisable dict.
            format:   ``"json"`` or ``"markdown"``.
            metadata: Optional metadata dict written alongside the report.

        Returns:
            The freshly-generated UUID4 report id (also used in the filename).
        """
        fmt = self._check_format(format)
        if fmt == "markdown" and not isinstance(content, str):
            raise ReportStoreError("markdown raporları string olarak iletilmelidir")
        self._maybe_prune()
        report_id = str(uuid.uuid4())
        target = self._resolve_path(report_id, fmt)
        envelope: Dict[str, Any] = {
            "report_id": report_id,
            "format": fmt,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "metadata": dict(metadata or {}),
            "schema": REPORT_SCHEMA_VERSION,
        }

        written: List[Path] = []
        try:
            if fmt == "json":
                envelope["content"] = content
                atomic_write_text(
                    target, json.dumps(envelope, ensure_ascii=False, default=str, indent=2)
                )
                written.append(target)
            else:  # markdown
                atomic_write_text(target, content)  # type: ignore[arg-type]
                written.append(target)
                # Sidecar metadata so list/get can return more than just bytes.
                sidecar = self._sidecar(target)
                atomic_write_text(
                    sidecar, json.dumps(envelope, ensure_ascii=False, default=str, indent=2)
                )
                written.append(sidecar)
        except OSError as exc:
            for path in written:  # no half-saved report
                self._remove(path)
            log.warning("Failed to write report %s (%s).", _short(report_id), type(exc).__name__)
            raise ReportStoreError("Rapor kalıcılığı başarısız oldu") from exc

        return report_id

    def get_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        """
        ``{"report_id", "format", "created_at", "metadata", "content", "schema"}``
        döner veya rapor yoksa ``None`` döner. ``schema`` eksikse rapor bu
        sürümden önce yazılmıştır.

        Raises:
            ReportStoreError: *report_id* geçerli bir UUID4 string değilse.
        """
        self._check_report_id(report_id)

        for fmt in _EXTENSIONS:
            path = self._resolve_path(report_id, fmt)
            if not path.exists():
                continue
            try:
                if fmt == "json":
                    raw = json.loads(path.read_text(encoding="utf-8"))
                    return raw if isinstance(raw, dict) else None
                # markdown
                content = path.read_text(encoding="utf-8")
                sidecar = self._sidecar(path)
                meta: Dict[str, Any] = {}
                created_at: Optional[str] = None
                schema: Any = None
                if sidecar.exists():
                    raw_meta = json.loads(sidecar.read_text(encoding="utf-8"))
                    if isinstance(raw_meta, dict):
                        meta = raw_meta.get("metadata", {}) or {}
                        created_at = raw_meta.get("created_at")
                        schema = raw_meta.get("schema")
                return {
                    "report_id": report_id,
                    "format": fmt,
                    "created_at": created_at,
                    "metadata": meta,
                    "content": content,
                    "schema": schema,
                }
            except (OSError, ValueError) as exc:
                log.warning("Bozuk rapor dosyası %s (%s).", _short(report_id), type(exc).__name__)
                return None
        return None

    def delete_report(self, report_id: str) -> bool:
        """Saklanmış bir raporu siler. Bir şey silindiyse True döner."""
        self._check_report_id(report_id)
        removed = False
        for fmt in _EXTENSIONS:
            path = self._resolve_path(report_id, fmt)
            if path.exists():
                try:
                    path.unlink()
                    removed = True
                except OSError as exc:
                    log.warning("Failed to delete report %s (%s).",
                                _short(report_id), type(exc).__name__)
            self._remove(self._sidecar(path))
        return removed

    def prune(self) -> Dict[str, int]:
        """
        Delete reports older than the retention period, then — while the
        directory is over its size limit — the oldest remaining ones, plus
        leftovers of interrupted writes. Only UUID-named report files (and
        their sidecars) directly in the report directory are touched; a file
        that vanishes meanwhile is skipped. Counts are reports, not files.
        """
        removed = {"expired": 0, "over_quota": 0}
        now = self._clock()
        cutoff = now - self._retention_days * _DAY_SECONDS
        kept: List[Tuple[float, int, List[Path]]] = []
        for path in self._report_files():
            files = [path] + ([self._sidecar(path)] if path.suffix == ".md" else [])
            try:
                stat = path.stat()
            except OSError:
                continue
            if stat.st_mtime < cutoff:
                removed["expired"] += self._remove_report(files)
            else:
                kept.append((stat.st_mtime, sum(self._size(f) for f in files), files))

        total = sum(size for _, size, _ in kept)
        limit = self._max_total_mb * 1024 * 1024
        for _, size, files in sorted(kept, key=lambda item: item[0]):
            if total <= limit:
                break
            if self._remove_report(files):
                removed["over_quota"] += 1
                total -= size

        self._remove_stale_temps(now)
        if removed["expired"] or removed["over_quota"]:
            log.info("Report store pruned — %d expired, %d over the size limit.",
                     removed["expired"], removed["over_quota"])
        return removed

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _check_format(fmt: str) -> str:
        if not isinstance(fmt, str):
            raise ReportStoreError("format bir string olmalıdır")
        f = fmt.strip().lower()
        if f not in _ALLOWED_FORMATS:
            raise ReportStoreError(
                f"format {_ALLOWED_FORMATS} değerlerinden biri olmalıdır, alınan '{fmt}'"
            )
        return f

    @staticmethod
    def _check_report_id(report_id: str) -> None:
        if not isinstance(report_id, str) or not _REPORT_ID_RE.fullmatch(report_id):
            raise ReportStoreError("report_id bir UUID4 string olmalıdır")

    def _resolve_path(self, report_id: str, fmt: str) -> Path:
        """
        Compute the absolute target path for *report_id* and assert that it
        sits *inside* ``self._base_dir``. This is the path-traversal guard.
        """
        self._check_report_id(report_id)
        candidate = (self._base_dir / f"{report_id}{_EXTENSIONS[fmt]}").resolve()
        try:
            candidate.relative_to(self._base_dir)
        except ValueError as exc:
            # Savunmacı: sabit uzantılı bir UUID4 temel dizini aşamaz, yine de
            # refactor'ların bu korumayı bozmaması için kontrol tutulsun.
            raise ReportStoreError("path traversal tespit edildi") from exc
        return candidate

    @staticmethod
    def _sidecar(path: Path) -> Path:
        return path.with_name(path.name + _SIDECAR_SUFFIX)

    def _maybe_prune(self) -> None:
        now = self._clock()
        if self._last_prune is not None and now - self._last_prune < PRUNE_INTERVAL_SECONDS:
            return
        if not self._prune_lock.acquire(blocking=False):
            return  # another thread is pruning
        try:
            self._last_prune = now
            self.prune()
        except OSError as exc:
            log.warning("Report pruning failed (%s).", type(exc).__name__)
        finally:
            self._prune_lock.release()

    def _scan(self, pattern: re.Pattern) -> List[Path]:
        try:
            with os.scandir(self._base_dir) as entries:
                return [
                    Path(entry.path) for entry in entries
                    if pattern.match(entry.name) and entry.is_file(follow_symlinks=False)
                ]
        except OSError:
            return []

    def _report_files(self) -> List[Path]:
        return self._scan(_REPORT_FILE_RE)

    def _remove_stale_temps(self, now: float) -> None:
        for path in self._scan(_TEMP_FILE_RE):
            try:
                if now - path.stat().st_mtime > _STALE_TEMP_SECONDS:
                    self._remove(path)
            except OSError:
                continue

    def _remove_report(self, files: List[Path]) -> int:
        main, *rest = files
        if not self._remove(main):
            return 0
        for path in rest:
            self._remove(path)
        return 1

    @staticmethod
    def _size(path: Path) -> int:
        try:
            return path.stat().st_size
        except OSError:
            return 0

    @staticmethod
    def _remove(path: Path) -> bool:
        try:
            path.unlink()
            return True
        except OSError:
            return False
