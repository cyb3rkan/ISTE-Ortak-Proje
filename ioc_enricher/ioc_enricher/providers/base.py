"""
Abstract base class for all threat intelligence providers.

Design principles:
    - Every provider declares which IOC types it supports via ``SUPPORTED_IOC_TYPES``.
    - The orchestrator uses this declaration to avoid calling unsupported methods.
    - A single ``_request()`` method handles all HTTP mechanics: timeouts, retries,
      SSL verification, and rate-limit detection.
    - Providers NEVER expose raw API keys in error messages or logs.
"""
from __future__ import annotations

import threading
import time
from abc import ABC, abstractmethod
from contextlib import contextmanager
from typing import Any, Callable, Dict, FrozenSet, Iterator, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from ..models import IOCType, ProviderResult, ProviderStatus
from ..utils.logger import get_logger
from ..utils.rate_limiter import RateLimiter, retry_after_seconds

log = get_logger(__name__)

# Shared rate limiter instance (injected by the orchestrator)
_default_limiter = RateLimiter()

# Deadline (a ``time.monotonic()`` reading) of the enrichment the current
# thread is working for; set by the aggregator through ``call_deadline``.
_call_context = threading.local()


@contextmanager
def call_deadline(deadline: Optional[float]) -> Iterator[None]:
    """
    Bound every provider request this thread makes inside the block by
    *deadline* (``None``: no deadline). Nothing is sent once it has passed,
    and the rate-limit wait and the HTTP timeouts shrink to end before it.
    """
    previous = getattr(_call_context, "deadline", None)
    _call_context.deadline = deadline
    try:
        yield
    finally:
        _call_context.deadline = previous


class _CircuitState:
    """
    Sağlayıcı bazında circuit breaker — yalnızca *geçici* hatalar için.

    Hata sayılanlar: retry'lardan sonra kalan 5xx, timeout, bağlantı hatası
    ve JSON olmayan 2xx gövde. Diğer her HTTP cevabı (400/401/403/404/422
    dahil) sağlayıcının ulaşılabilir olduğunu gösterir ve sayacı sıfırlar;
    HTTP 429 rate limiter'ın işidir, devreye dokunmaz.

    Ardışık FAILURE_THRESHOLD hata sonrası devre açılır. RECOVERY_TIMEOUT_SECONDS
    geçince half-open: tam olarak bir deneme isteği geçer; başarılıysa devre
    kapanır, başarısızsa yeniden açılır. Sonuçsuz kalan bir deneme (ör. rate
    limit) bir recovery süresi sonra yenisiyle değiştirilir.
    """

    FAILURE_THRESHOLD: int = 5
    RECOVERY_TIMEOUT_SECONDS: float = 60.0

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self.failures = 0
        self.opened_at: Optional[float] = None
        self._trial_at: Optional[float] = None

    def allow_request(self) -> bool:
        """True when a request may be sent now (closed, or the half-open trial)."""
        with self._lock:
            if self.opened_at is None:
                return True
            now = self._clock()
            if now - self.opened_at < self.RECOVERY_TIMEOUT_SECONDS:
                return False
            if (
                self._trial_at is not None
                and now - self._trial_at < self.RECOVERY_TIMEOUT_SECONDS
            ):
                return False
            self._trial_at = now
            return True

    def is_open(self) -> bool:
        with self._lock:
            return self.opened_at is not None

    def record_failure(self) -> None:
        with self._lock:
            if self.opened_at is not None:
                # The half-open trial (or a request already in flight) failed.
                self.opened_at = self._clock()
                self._trial_at = None
                return
            self.failures += 1
            if self.failures >= self.FAILURE_THRESHOLD:
                self.opened_at = self._clock()

    def record_success(self) -> None:
        with self._lock:
            self.failures = 0
            self.opened_at = None
            self._trial_at = None


class BaseProvider(ABC):
    """
    Abstract base for all TI providers.

    Subclasses must implement:
        - ``name`` property
        - ``SUPPORTED_IOC_TYPES`` class attribute
        - ``_get_headers()``
        - Relevant ``lookup_*`` methods for their supported IOC types
    """

    #: Set of IOC types this provider can handle.
    SUPPORTED_IOC_TYPES: FrozenSet[IOCType] = frozenset()

    #: Connect timeout of one HTTP attempt (the read timeout is ``timeout``).
    CONNECT_TIMEOUT_SECONDS: float = 10.0
    #: After HTTP 401 (API key rejected) the provider is not queried again
    #: for this long: every IOC would get the same answer.
    AUTH_RETRY_SECONDS: float = 300.0

    def __init__(
        self,
        api_key: str,
        timeout: int = 30,
        rate_limiter: Optional[RateLimiter] = None,
    ) -> None:
        self._api_key = api_key          # never logged
        self._timeout = timeout
        self._limiter = rate_limiter or _default_limiter
        self._session = self._build_session()
        self._clock: Callable[[], float] = time.monotonic
        self._circuit = _CircuitState(clock=lambda: self._clock())
        self._auth_rejected_until = 0.0

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable provider name (must match rate-limiter config)."""

    @abstractmethod
    def _get_headers(self) -> Dict[str, str]:
        """Return HTTP headers required by this provider's API."""

    # ------------------------------------------------------------------
    # Lookup stubs — override only the ones your provider supports
    # ------------------------------------------------------------------

    def lookup_ip(self, ip: str) -> ProviderResult:
        return self._unsupported("IP lookup")

    def lookup_domain(self, domain: str) -> ProviderResult:
        return self._unsupported("domain lookup")

    def lookup_hash(self, file_hash: str) -> ProviderResult:
        return self._unsupported("hash lookup")

    def lookup_url(self, url: str) -> ProviderResult:
        return self._unsupported("URL lookup")

    def lookup_email(self, email: str) -> ProviderResult:
        return self._unsupported("email lookup")

    def supports(self, ioc_type: IOCType) -> bool:
        """Return True when this provider handles *ioc_type*."""
        return ioc_type in self.SUPPORTED_IOC_TYPES

    # ------------------------------------------------------------------
    # HTTP engine
    # ------------------------------------------------------------------

    def _build_session(self) -> requests.Session:
        """Create a hardened requests session with retry logic."""
        session = requests.Session()
        # Retry budget: at most 2 retries for connection errors / 5xx. Read
        # timeouts are *not* retried — the call already waited the full read
        # timeout, and retrying would multiply the worst-case latency per IOC
        # (and per batch) without much chance of success. The per-provider
        # circuit breaker handles sustained failures. Retry-After is not
        # slept here: urllib3 would block the worker for up to 6 hours on a
        # 429/503; 429 pauses the provider in the rate limiter instead.
        retry = Retry(
            total=2,
            read=0,
            backoff_factor=1,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["GET", "POST"],
            raise_on_status=False,
            respect_retry_after_header=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("https://", adapter)
        # HTTP adapter kasıtlı olarak mount edilmemiştir.
        # requests.Session() varsayılan bir http:// adapter'ı kurar; onu
        # da kaldırıyoruz. Tüm provider istekleri HTTPS zorunludur — hem
        # transport seviyesinde (adapter yok) hem de _request() metodunda
        # (URL kontrolü) çift katman güvence sağlanmaktadır.
        session.adapters.pop("http://", None)
        session.headers.update(self._get_headers())
        return session

    def _request(
        self,
        method: str,
        url: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        form_body: Optional[Dict[str, Any]] = None,
    ) -> ProviderResult:
        """
        Execute a single HTTP request, handling rate-limiting and errors.

        Args:
            method:     HTTP method string ("GET", "POST").
            url:        Full endpoint URL (must use HTTPS).
            params:     Query string parameters.
            json_body:  JSON request body.
            form_body:  ``application/x-www-form-urlencoded`` body — for APIs
                        that take the key as a parameter, so it stays out of
                        the URL (and so out of any URL-logging layer).

        Returns:
            :class:`ProviderResult` — never raises.

        Inside :func:`call_deadline` nothing is sent once the deadline has
        passed, and the rate-limit wait and the HTTP timeouts shrink to end
        before it.
        """
        if not url.startswith("https://"):
            return ProviderResult(
                provider=self.name,
                status=ProviderStatus.ERROR,
                error="Insecure HTTP endpoint rejected — HTTPS required.",
            )

        deadline: Optional[float] = getattr(_call_context, "deadline", None)
        now = self._clock()
        if deadline is not None and now >= deadline:
            return self._past_deadline()

        if now < self._auth_rejected_until:
            return ProviderResult(
                provider=self.name,
                status=ProviderStatus.ERROR,
                error=(
                    f"HTTP 401: {self.name} rejected the API key; not queried again "
                    f"for {self._auth_rejected_until - now:.0f}s."
                ),
            )

        # Circuit breaker — ardışık geçici hatalar sonrası geçici olarak devre dışı
        if not self._circuit.allow_request():
            return ProviderResult(
                provider=self.name,
                status=ProviderStatus.ERROR,
                error=f"{self.name} circuit breaker açık — geçici olarak devre dışı.",
            )

        # Rate limiting before each request; never waits past the deadline.
        if not self._limiter.wait(
            self.name, max_wait=None if deadline is None else deadline - now
        ):
            return ProviderResult(
                provider=self.name,
                status=ProviderStatus.RATE_LIMITED,
                error=f"Rate limit: no {self.name} request slot within the wait budget; not sent.",
            )

        connect_timeout = self.CONNECT_TIMEOUT_SECONDS
        read_timeout = float(self._timeout)
        capped = False
        if deadline is not None:
            remaining = deadline - self._clock()
            if remaining <= 0:
                return self._past_deadline()
            if remaining < max(connect_timeout, read_timeout):
                capped = True
                connect_timeout = min(connect_timeout, remaining)
                read_timeout = min(read_timeout, remaining)

        start = time.monotonic()
        try:
            # The URL path carries the IOC: log the provider only.
            log.debug("→ %s %s", self.name, method)
            resp = self._session.request(
                method,
                url,
                params=params,
                json=json_body,
                data=form_body,
                timeout=(connect_timeout, read_timeout),
                verify=True,
            )
            elapsed = time.monotonic() - start

            if resp.status_code == 429:
                # A rate limit, not an outage: the limiter pauses the provider
                # for its Retry-After (bounded); the circuit is left alone.
                paused = self._limiter.backoff(
                    self.name, retry_after_seconds(resp.headers.get("Retry-After"))
                )
                return ProviderResult(
                    provider=self.name,
                    status=ProviderStatus.RATE_LIMITED,
                    error=f"Rate limit exceeded (HTTP 429); {self.name} paused for {paused:.0f}s.",
                    response_time=elapsed,
                )

            if resp.status_code == 404:
                # NOT_FOUND başarılı bir cevap — provider sağlıklı.
                self._circuit.record_success()
                return ProviderResult(
                    provider=self.name,
                    status=ProviderStatus.NOT_FOUND,
                    response_time=elapsed,
                )

            if resp.status_code >= 500:
                # A server-side failure that survived the retries: transient.
                self._circuit.record_failure()
                return ProviderResult(
                    provider=self.name,
                    status=ProviderStatus.ERROR,
                    error=f"HTTP {resp.status_code}",
                    response_time=elapsed,
                )

            if resp.status_code >= 400:
                # The provider answered (bad request, rejected key, forbidden,
                # unprocessable): reachable, so no outage for the circuit; the
                # adapter gives the code its meaning.
                self._circuit.record_success()
                if resp.status_code == 401:
                    self._auth_rejected_until = self._clock() + self.AUTH_RETRY_SECONDS
                    log.warning(
                        "%s rejected the API key (HTTP 401); not queried again for %.0fs.",
                        self.name, self.AUTH_RETRY_SECONDS,
                    )
                return ProviderResult(
                    provider=self.name,
                    status=ProviderStatus.ERROR,
                    error=f"HTTP {resp.status_code}",
                    response_time=elapsed,
                )

            try:
                data: Any = resp.json()
            except ValueError:
                data = None
            if not isinstance(data, dict):
                # Every provider answers with a JSON object. Anything else (a
                # proxy's HTML error page, an empty or truncated body, a bare
                # list) is a broken answer, never a successful or clean one;
                # for the circuit breaker it is a transient failure. The body
                # itself is not echoed.
                self._circuit.record_failure()
                return ProviderResult(
                    provider=self.name,
                    status=ProviderStatus.ERROR,
                    error=f"Invalid response from {self.name}: body is not a JSON object.",
                    response_time=elapsed,
                )

            log.debug(
                "← %s %s [%.2fs]", resp.status_code, self.name, elapsed
            )
            self._circuit.record_success()
            return ProviderResult(
                provider=self.name,
                status=ProviderStatus.SUCCESS,
                data=data,
                response_time=elapsed,
            )

        except requests.exceptions.Timeout:
            if capped:
                # The enrichment deadline, not the provider, cut this short.
                return ProviderResult(
                    provider=self.name,
                    status=ProviderStatus.TIMEOUT,
                    error="Request stopped at the enrichment deadline.",
                    response_time=time.monotonic() - start,
                )
            self._circuit.record_failure()
            return ProviderResult(
                provider=self.name,
                status=ProviderStatus.TIMEOUT,
                error=f"Request timed out after {self._timeout}s.",
                response_time=time.monotonic() - start,
            )
        except requests.exceptions.RequestException as exc:
            # Sanitise the exception message to avoid leaking key material
            safe_msg = str(exc).replace(self._api_key, "***")[:200]
            self._circuit.record_failure()
            return ProviderResult(
                provider=self.name,
                status=ProviderStatus.ERROR,
                error=f"Network error: {safe_msg}",
                response_time=time.monotonic() - start,
            )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _past_deadline(self) -> ProviderResult:
        return ProviderResult(
            provider=self.name,
            status=ProviderStatus.TIMEOUT,
            error="Enrichment deadline reached before the request was sent.",
        )

    def _invalid(self, result: ProviderResult, detail: str) -> ProviderResult:
        """Turn a 2xx answer whose body breaks the contract into an error."""
        result.status = ProviderStatus.ERROR
        result.data = None
        result.error = f"Invalid response from {self.name}: {detail}."
        return result

    def _unsupported(self, operation: str) -> ProviderResult:
        return ProviderResult(
            provider=self.name,
            status=ProviderStatus.UNSUPPORTED,
            error=f"{operation} is not supported by {self.name}.",
        )

    def __del__(self) -> None:
        try:
            self._session.close()
        except Exception:
            pass
