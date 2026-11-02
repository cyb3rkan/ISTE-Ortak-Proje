"""
Web katmanı ayarları.

Ortam değişkenlerinden okunur; makul ve güvenli varsayılanlar kullanılır. Ek
bir bağımlılıktan kaçınmak için burada ``pydantic-settings`` miras alınmaz; ihtiyaç
duyduğumuz alanlar el yapımı bir ``Settings`` dataclass ile daha net ifade
edilebilir.

Ortam değişkenleri (tümü opsiyoneldir):

- ``IOC_WEB_DEBUG``                  — ``true``/``false`` (varsayılan false). False
  iken dağıtım üretim benzeri sayılır.
- ``IOC_WEB_API_PREFIX``             — varsayılan ``/api/v1``.
- ``IOC_WEB_ENABLE_DOCS``            — ``/docs``, ``/redoc`` ve ``/openapi.json``.
  Boş/ayarsız ise yalnızca debug modunda açıktır; ``true``/``false`` her zaman
  önceliklidir. Üretimde açılırsa başlangıçta uyarı loglanır.
- ``IOC_WEB_CORS_ALLOWED_ORIGINS``   — virgülle ayrılmış köken listesi. Varsayılan:
  sadece localhost geliştirme kökenleri. **Asla** ``*`` ile yedeklenmez.
- ``IOC_WEB_RATE_LIMIT_ENABLED``     — varsayılan true.
- ``IOC_WEB_RATE_LIMIT_PER_MIN``     — varsayılan 30 (tek IOC enrich için).
- ``IOC_WEB_BATCH_RATE_LIMIT_PER_MIN`` — varsayılan 5.
- ``IOC_WEB_CLEAR_CACHE_PER_MIN``    — varsayılan 1.
- ``IOC_WEB_MAX_BODY_BYTES``         — varsayılan 262144 (256 KiB).
- ``IOC_WEB_LOGIN_RATE_LIMIT_PER_MIN``   — varsayılan 10 (``POST /auth/login``, istemci başına).
- ``IOC_WEB_REFRESH_RATE_LIMIT_PER_MIN`` — varsayılan 30 (``POST /auth/refresh``, istemci başına).
- ``IOC_WEB_TRUST_PROXY_HEADERS``    — varsayılan false. True ise,
  ``X-Forwarded-For`` per-IP rate-limit anahtarları için dikkate alınır —
  ancak *yalnızca* doğrudan bağlanan peer ``IOC_WEB_TRUSTED_PROXIES`` içindeyse.
- ``IOC_WEB_TRUSTED_PROXIES``        — virgülle ayrılmış IP/CIDR listesi (ör.
  ``10.0.0.0/8,fd00::/8``). Boşsa ``X-Forwarded-For`` hiçbir zaman dikkate alınmaz.
- ``IOC_WEB_ACCESS_LOG_IP_KEY``      — opsiyonel sır. Erişim logundaki istemci
  IP takma adının (HMAC) anahtarı; ayarlanırsa takma ad yeniden başlatmalar ve
  worker'lar arasında sabit kalır. Ayarlanmazsa her uygulama örneği rastgele
  bir anahtar kullanır (yalnızca süreç içinde ilişkilendirme).
- ``IOC_WEB_BATCH_DEADLINE_SECONDS`` — varsayılan 120. Bir batch isteğinin toplam
  süre bütçesi; aşıldığında kalan IOC'ler ``deadline_exceeded`` hatası ile döner.

Auth (Phase 2.5):

- ``IOC_WEB_AUTH_ENABLED``           — varsayılan false. Kullanıcı auth'u da
  kapalıysa API kapalı kalır: korumalı rotalar 503, admin rotaları 403 döner.
- ``IOC_WEB_DEV_ALLOW_UNAUTHENTICATED`` — varsayılan false. Yalnızca yerel
  geliştirme içindir: iki auth modu da kapalıyken admin olmayan rotaları
  anahtarsız açar; admin rotaları kapalı kalır. ``IOC_WEB_DEBUG=true``
  gerektirir — aksi hâlde uygulama başlamayı reddeder.
- ``IOC_WEB_API_KEYS``               — korumalı rotalarda kabul edilen API anahtarları,
  virgülle ayrılmış liste. Varsayılan boş.
- ``IOC_WEB_ADMIN_API_KEYS``         — admin rotalarında (``DELETE /cache``)
  kabul edilen admin anahtarları. Varsayılan boş.
- ``IOC_WEB_REQUIRE_STRONG_API_KEYS_IN_PROD`` — varsayılan true. API
  anahtarları JWT sırrıyla aynı ölçüte tabidir: yer tutucular her modda,
  zayıf (kısa, tekrarlı, ardışık) anahtarlar debug'da ve üretimde
  reddedilir. False yalnızca üretim benzeri modda zayıf anahtar kuralını
  gevşetir; yer tutucuları ve debug modunu gevşetmez.
- ``IOC_WEB_API_KEY_HEADER_NAME``         — varsayılan ``X-API-Key``.
- ``IOC_WEB_ADMIN_API_KEY_HEADER_NAME``   — varsayılan ``X-Admin-API-Key``.
- ``IOC_WEB_ALLOW_HEALTH_WITHOUT_AUTH``   — varsayılan true.
- ``IOC_WEB_ALLOW_DOCS_WITHOUT_AUTH``     — varsayılan true. False ise
  dokümantasyon hiç servis edilmez (kimlik doğrulamalı docs desteklenmez).

HSTS:

- ``IOC_WEB_HSTS_ENABLED``           — varsayılan false (HTTP geliştirme baz çizgisi).
  Sadece HTTPS ile servis edilirken true yapılmalıdır.
- ``IOC_WEB_HSTS_MAX_AGE``           — varsayılan 31_536_000 (bir yıl).

Kullanıcı auth (Phase 5a) — tarayıcı tarafı JWT girişi:

- ``IOC_WEB_USER_AUTH_ENABLED``      — varsayılan false. True ise ``/auth/*``
  uç noktaları aktif olur ve korumalı rotalar API anahtarına ek olarak Bearer JWT
  kabul eder.
- ``IOC_WEB_JWT_SECRET_KEY``         — HMAC imzalama sırrı. Kullanıcı auth etkin
  ise gereklidir; yer tutucu, kısa, tekrarlı veya sıralı sırlar debug dahil
  her modda reddedilir.
- ``IOC_WEB_JWT_ALGORITHM``          — varsayılan ``HS256``.
- ``IOC_WEB_ACCESS_TOKEN_TTL_MINUTES`` — varsayılan 15.
- ``IOC_WEB_REFRESH_TOKEN_TTL_DAYS`` — varsayılan 7.
- ``IOC_WEB_REFRESH_COOKIE_NAME``    — varsayılan ``ioc_refresh_token``.
- ``IOC_WEB_CSRF_COOKIE_NAME``       — varsayılan ``ioc_csrf_token``.
- ``IOC_WEB_CSRF_COOKIE_PATH``       — varsayılan ``/``. SPA'nın her sayfadan
  ``document.cookie`` ile okuyabilmesi için site genelinde olmalıdır.
- ``IOC_WEB_REFRESH_COOKIE_SECURE``  — varsayılan false (yerel HTTP). HTTPS altında true yapılmalı.
- ``IOC_WEB_REFRESH_COOKIE_SAMESITE`` — varsayılan ``lax``.
- ``IOC_WEB_REFRESH_COOKIE_PATH``    — varsayılan ``/api/v1/auth``.
- ``IOC_WEB_BOOTSTRAP_ADMIN_USERNAME`` — bootstrap giriş kullanıcı adı.
- ``IOC_WEB_BOOTSTRAP_ADMIN_PASSWORD_HASH`` — parola için argon2 hash.
- ``IOC_WEB_BOOTSTRAP_ADMIN_ROLE``   — varsayılan ``admin``.
- ``IOC_WEB_REQUIRE_STRONG_JWT_SECRET_IN_PROD`` — varsayılan true. False
  yalnızca üretim benzeri modda uzunluk/çeşitlilik kuralını gevşetir; debug
  modunu gevşetmez.
- ``IOC_WEB_REDIS_URL``              — opsiyonel. Ayarlandığında Redis tabanlı rate
  limiting ve refresh-token iptali etkinleşir.

Yukarıdaki sır içeren değerlerin hiçbiri loglanmaz, bir yanıtta dönülmez veya
OpenAPI şemasında gösterilmez.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Optional

from .. import __version__ as _PKG_VERSION


_DEFAULT_CORS_ORIGINS: List[str] = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]


def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "on"}


def _env_optional_bool(name: str) -> Optional[bool]:
    """Like :func:`_env_bool`, but unset or blank means ``None`` ("not set")."""
    v = os.getenv(name)
    if v is None or not v.strip():
        return None
    return v.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    if v is None or not v.strip():
        return default
    try:
        return int(v)
    except ValueError:
        return default


def _env_list(name: str, default: List[str]) -> List[str]:
    v = os.getenv(name)
    if v is None or not v.strip():
        return list(default)
    items = [s.strip() for s in v.split(",") if s.strip()]
    # Defensive: reject the wildcard so a misconfigured env var can never
    # silently disable CORS in production.
    items = [i for i in items if i != "*"]
    return items or list(default)


def _env_csv(name: str) -> List[str]:
    """Read a plain (non-secret) comma-separated list; empty items dropped."""
    v = os.getenv(name)
    if v is None or not v.strip():
        return []
    return [s.strip() for s in v.split(",") if s.strip()]


def _env_str(name: str) -> Optional[str]:
    """Read an optional *secret* string from env without logging it."""
    v = os.getenv(name)
    if v is None:
        return None
    v = v.strip()
    return v or None


def _env_secret_list(name: str) -> List[str]:
    """
    Read a comma-separated *secret* list from env without ever logging it.

    Empty values are dropped; surrounding whitespace is stripped. We do not
    log the count or any prefix here — the list is treated as opaque secret
    material.
    """
    v = os.getenv(name)
    if v is None or not v.strip():
        return []
    return [s.strip() for s in v.split(",") if s.strip()]


@dataclass(frozen=True)
class WebSettings:
    """Immutable configuration snapshot for the FastAPI layer."""

    app_name: str = "IOC Enricher API"
    app_version: str = _PKG_VERSION
    api_prefix: str = "/api/v1"
    debug: bool = False
    # None: serve the docs in debug mode only (see app._docs_enabled).
    enable_docs: Optional[bool] = None

    cors_allowed_origins: List[str] = field(default_factory=lambda: list(_DEFAULT_CORS_ORIGINS))

    rate_limit_enabled: bool = True
    rate_limit_per_minute: int = 30
    batch_rate_limit_per_minute: int = 5
    clear_cache_per_minute: int = 1

    login_rate_limit_per_minute: int = 10
    refresh_rate_limit_per_minute: int = 30

    max_request_body_bytes: int = 256 * 1024
    trust_proxy_headers: bool = False
    trusted_proxies: List[str] = field(default_factory=list)
    # HMAC key for the access log's client-IP pseudonym; None = random per
    # app instance. A secret: never part of repr().
    access_log_ip_key: Optional[str] = field(default=None, repr=False)

    batch_deadline_seconds: float = 120.0

    # ----- Phase 2.5: API key auth ---------------------------------------
    auth_enabled: bool = False
    api_key_header_name: str = "X-API-Key"
    admin_api_key_header_name: str = "X-Admin-API-Key"
    api_keys: List[str] = field(default_factory=list)
    admin_api_keys: List[str] = field(default_factory=list)
    require_strong_api_keys_in_prod: bool = True
    allow_health_without_auth: bool = True
    allow_docs_without_auth: bool = True
    # Local development only; requires debug (refused at startup otherwise).
    dev_allow_unauthenticated: bool = False

    # ----- HSTS -----------------------------------------------------------
    hsts_enabled: bool = False
    hsts_max_age: int = 31_536_000

    # ----- Phase 5a: browser user auth (JWT) ------------------------------
    user_auth_enabled: bool = False
    jwt_secret_key: Optional[str] = None
    jwt_algorithm: str = "HS256"
    access_token_ttl_minutes: int = 15
    refresh_token_ttl_days: int = 7
    refresh_cookie_name: str = "ioc_refresh_token"
    csrf_cookie_name: str = "ioc_csrf_token"
    csrf_cookie_path: str = "/"
    refresh_cookie_secure: bool = False
    refresh_cookie_samesite: str = "lax"
    refresh_cookie_path: str = "/api/v1/auth"
    bootstrap_admin_username: Optional[str] = None
    bootstrap_admin_password_hash: Optional[str] = None
    bootstrap_admin_role: str = "admin"
    require_strong_jwt_secret_in_prod: bool = True

    # ----- Phase 5b: Redis (rate limiting + token revocation) -------------
    redis_url: Optional[str] = None


def load_settings() -> WebSettings:
    """Build a :class:`WebSettings` from the current environment."""
    return WebSettings(
        debug=_env_bool("IOC_WEB_DEBUG", False),
        api_prefix=os.getenv("IOC_WEB_API_PREFIX", "/api/v1") or "/api/v1",
        enable_docs=_env_optional_bool("IOC_WEB_ENABLE_DOCS"),
        cors_allowed_origins=_env_list(
            "IOC_WEB_CORS_ALLOWED_ORIGINS", _DEFAULT_CORS_ORIGINS
        ),
        rate_limit_enabled=_env_bool("IOC_WEB_RATE_LIMIT_ENABLED", True),
        rate_limit_per_minute=_env_int("IOC_WEB_RATE_LIMIT_PER_MIN", 30),
        batch_rate_limit_per_minute=_env_int("IOC_WEB_BATCH_RATE_LIMIT_PER_MIN", 5),
        clear_cache_per_minute=_env_int("IOC_WEB_CLEAR_CACHE_PER_MIN", 1),
        login_rate_limit_per_minute=_env_int("IOC_WEB_LOGIN_RATE_LIMIT_PER_MIN", 10),
        refresh_rate_limit_per_minute=_env_int(
            "IOC_WEB_REFRESH_RATE_LIMIT_PER_MIN", 30
        ),
        max_request_body_bytes=_env_int("IOC_WEB_MAX_BODY_BYTES", 256 * 1024),
        trust_proxy_headers=_env_bool("IOC_WEB_TRUST_PROXY_HEADERS", False),
        trusted_proxies=_env_csv("IOC_WEB_TRUSTED_PROXIES"),
        access_log_ip_key=_env_str("IOC_WEB_ACCESS_LOG_IP_KEY"),
        batch_deadline_seconds=float(
            _env_int("IOC_WEB_BATCH_DEADLINE_SECONDS", 120)
        ),
        auth_enabled=_env_bool("IOC_WEB_AUTH_ENABLED", False),
        api_key_header_name=os.getenv("IOC_WEB_API_KEY_HEADER_NAME", "X-API-Key")
        or "X-API-Key",
        admin_api_key_header_name=os.getenv(
            "IOC_WEB_ADMIN_API_KEY_HEADER_NAME", "X-Admin-API-Key"
        )
        or "X-Admin-API-Key",
        api_keys=_env_secret_list("IOC_WEB_API_KEYS"),
        admin_api_keys=_env_secret_list("IOC_WEB_ADMIN_API_KEYS"),
        require_strong_api_keys_in_prod=_env_bool(
            "IOC_WEB_REQUIRE_STRONG_API_KEYS_IN_PROD", True
        ),
        allow_health_without_auth=_env_bool("IOC_WEB_ALLOW_HEALTH_WITHOUT_AUTH", True),
        allow_docs_without_auth=_env_bool("IOC_WEB_ALLOW_DOCS_WITHOUT_AUTH", True),
        dev_allow_unauthenticated=_env_bool("IOC_WEB_DEV_ALLOW_UNAUTHENTICATED", False),
        hsts_enabled=_env_bool("IOC_WEB_HSTS_ENABLED", False),
        hsts_max_age=_env_int("IOC_WEB_HSTS_MAX_AGE", 31_536_000),
        user_auth_enabled=_env_bool("IOC_WEB_USER_AUTH_ENABLED", False),
        jwt_secret_key=_env_str("IOC_WEB_JWT_SECRET_KEY"),
        jwt_algorithm=os.getenv("IOC_WEB_JWT_ALGORITHM", "HS256") or "HS256",
        access_token_ttl_minutes=_env_int("IOC_WEB_ACCESS_TOKEN_TTL_MINUTES", 15),
        refresh_token_ttl_days=_env_int("IOC_WEB_REFRESH_TOKEN_TTL_DAYS", 7),
        refresh_cookie_name=os.getenv(
            "IOC_WEB_REFRESH_COOKIE_NAME", "ioc_refresh_token"
        )
        or "ioc_refresh_token",
        csrf_cookie_name=os.getenv("IOC_WEB_CSRF_COOKIE_NAME", "ioc_csrf_token")
        or "ioc_csrf_token",
        csrf_cookie_path=os.getenv("IOC_WEB_CSRF_COOKIE_PATH", "/") or "/",
        refresh_cookie_secure=_env_bool("IOC_WEB_REFRESH_COOKIE_SECURE", False),
        refresh_cookie_samesite=(
            os.getenv("IOC_WEB_REFRESH_COOKIE_SAMESITE", "lax") or "lax"
        ).strip().lower(),
        refresh_cookie_path=os.getenv(
            "IOC_WEB_REFRESH_COOKIE_PATH", "/api/v1/auth"
        )
        or "/api/v1/auth",
        bootstrap_admin_username=_env_str("IOC_WEB_BOOTSTRAP_ADMIN_USERNAME"),
        bootstrap_admin_password_hash=_env_str(
            "IOC_WEB_BOOTSTRAP_ADMIN_PASSWORD_HASH"
        ),
        bootstrap_admin_role=(
            os.getenv("IOC_WEB_BOOTSTRAP_ADMIN_ROLE", "admin") or "admin"
        ).strip().lower(),
        require_strong_jwt_secret_in_prod=_env_bool(
            "IOC_WEB_REQUIRE_STRONG_JWT_SECRET_IN_PROD", True
        ),
        redis_url=_env_str("IOC_WEB_REDIS_URL"),
    )
