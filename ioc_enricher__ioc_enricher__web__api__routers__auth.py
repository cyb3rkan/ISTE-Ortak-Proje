"""
Tarayıcı kullanıcı-doğrulama (authentication) uç noktaları (Aşama 5a).

Rotalar (tümü ``{api_prefix}/auth`` altında):

- ``POST /auth/login``   — kullanıcı adı/şifre -> erişim token'ı + yenileme cookie'si
                           + CSRF cookie.
- ``POST /auth/refresh`` — yenileme cookie'si + CSRF header -> yeni erişim token'ı.
- ``POST /auth/logout``  — cookie'leri temizler, refresh token jti'sini iptal eder.
- ``GET  /auth/me``      — geçerli kullanıcıyı döner (Bearer erişim token'ı).

Token saklama anlaşması:

- **access token** JSON gövdesinde döner. Tarayıcı sadece bellekte tutar — burada
  cookie olarak ayarlanmaz.
- **refresh token** yalnızca httpOnly, SameSite cookie olarak teslim edilir — JS
  tarafından okunamaz.
- **CSRF token** okunabilir (non-httpOnly) cookie olarak verilir; tarayıcı
  refresh/logout sırasında bunu ``X-CSRF-Token`` başlığında geri gönderir.

``user_auth_enabled`` false ise her rota güvenli bir 404 döner. Etkin ancak JWT
secret eksik/zayıf ise rotalar güvenli bir 503 döner.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from ....web.settings import WebSettings
from ..deps import get_settings
from ..security.auth import (
    AuthForbiddenError,
    AuthRequiredError,
    AuthUnavailableError,
)
from ..security.csrf import create_csrf_token, verify_csrf
from ..security.jwt_tokens import (
    REFRESH_TOKEN_TYPE,
    TokenError,
    create_access_token,
    create_refresh_token,
    decode_token,
)
from ..security.token_store import TokenDenylist, TokenStoreUnavailable
from ..security.user_auth import (
    AuthConfigError,
    JwtConfig,
    account_for_token,
    authenticate_bootstrap_user,
    credential_fingerprint,
    require_user,
    resolve_jwt_config,
)

log = logging.getLogger("ioc_enricher.web.auth")

router = APIRouter(tags=["auth"], prefix="/auth")

_MAX_CRED_LEN = 256


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)

    username: str = Field(..., min_length=1, max_length=_MAX_CRED_LEN)
    password: str = Field(..., min_length=1, max_length=_MAX_CRED_LEN)


class UserInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str
    role: str


class TokenResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserInfo


class LogoutResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    logged_out: bool = True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ensure_user_auth_enabled(settings: WebSettings) -> None:
    """404 when user auth is disabled — the route effectively does not exist."""
    if not settings.user_auth_enabled:
        # Genel 404: özelliğin var olduğu fakat kapalı olduğu ilan edilmesin.
        raise HTTPException(status_code=404, detail="Bulunamadı")


def _ensure_jwt_config(settings: WebSettings) -> JwtConfig:
    """503 (safe) when the JWT secret is missing/weak or the algorithm is not allowed."""
    try:
        return resolve_jwt_config(settings)
    except AuthConfigError as exc:
        log.error("auth-misconfigured: %s", exc)
        raise AuthUnavailableError(
            "Kimlik doğrulama geçici olarak kullanılamıyor."
        ) from exc


def _denylist(request: Request) -> TokenDenylist:
    return request.app.state.token_denylist


def _set_auth_cookies(
    response: Response, settings: WebSettings, *, refresh_token: str, csrf_token: str
) -> None:
    refresh_max_age = settings.refresh_token_ttl_days * 24 * 3600
    response.set_cookie(
        key=settings.refresh_cookie_name,
        value=refresh_token,
        max_age=refresh_max_age,
        httponly=True,
        secure=settings.refresh_cookie_secure,
        samesite=settings.refresh_cookie_samesite,
        path=settings.refresh_cookie_path,
    )
    # CSRF cookie is intentionally readable by JS (double-submit pattern).
    # It must be site-wide: browsers only expose a cookie to document.cookie
    # when its path matches the *page* URL (e.g. /analyze), so the narrow
    # refresh-cookie path would hide it from the SPA.
    _delete_legacy_csrf_cookie(response, settings)
    response.set_cookie(
        key=settings.csrf_cookie_name,
        value=csrf_token,
        max_age=refresh_max_age,
        httponly=False,
        secure=settings.refresh_cookie_secure,
        samesite=settings.refresh_cookie_samesite,
        path=settings.csrf_cookie_path,
    )


def _delete_legacy_csrf_cookie(response: Response, settings: WebSettings) -> None:
    """Drop a CSRF cookie left at the old (refresh) path by earlier versions,
    so a browser never holds two same-named CSRF cookies."""
    if settings.refresh_cookie_path != settings.csrf_cookie_path:
        response.delete_cookie(
            key=settings.csrf_cookie_name,
            path=settings.refresh_cookie_path,
            secure=settings.refresh_cookie_secure,
            samesite=settings.refresh_cookie_samesite,
        )


def _clear_auth_cookies(response: Response, settings: WebSettings) -> None:
    response.delete_cookie(
        key=settings.refresh_cookie_name,
        path=settings.refresh_cookie_path,
        httponly=True,
        secure=settings.refresh_cookie_secure,
        samesite=settings.refresh_cookie_samesite,
    )
    response.delete_cookie(
        key=settings.csrf_cookie_name,
        path=settings.csrf_cookie_path,
        secure=settings.refresh_cookie_secure,
        samesite=settings.refresh_cookie_samesite,
    )
    _delete_legacy_csrf_cookie(response, settings)


def _issue_tokens(
    response: Response,
    settings: WebSettings,
    config: JwtConfig,
    *,
    username: str,
    role: str,
) -> TokenResponse:
    # Both tokens name the credential they were issued for, so a changed
    # password (or username) ends the session at its next use.
    credential = credential_fingerprint(settings, config.secret)
    access_token, _ = create_access_token(
        subject=username,
        role=role,
        secret=config.secret,
        algorithm=config.algorithm,
        ttl_minutes=settings.access_token_ttl_minutes,
        credential=credential,
    )
    refresh_token, _ = create_refresh_token(
        subject=username,
        role=role,
        secret=config.secret,
        algorithm=config.algorithm,
        ttl_days=settings.refresh_token_ttl_days,
        credential=credential,
    )
    csrf_token = create_csrf_token()
    _set_auth_cookies(
        response, settings, refresh_token=refresh_token, csrf_token=csrf_token
    )
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.access_token_ttl_minutes * 60,
        user=UserInfo(username=username, role=role),
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/login", response_model=TokenResponse, summary="Kullanıcı girişi")
def login(
    payload: LoginRequest,
    response: Response,
    settings: WebSettings = Depends(get_settings),
) -> TokenResponse:
    _ensure_user_auth_enabled(settings)
    config = _ensure_jwt_config(settings)

    user = authenticate_bootstrap_user(
        settings, payload.username, payload.password
    )
    if user is None:
        # Tekdüze, genel mesaj — hangi alanın hatalı olduğu asla açığa çıkarılmaz.
        raise AuthRequiredError("Geçersiz kullanıcı adı veya şifre.")

    return _issue_tokens(
        response, settings, config, username=user.username, role=user.role
    )


@router.post(
    "/refresh", response_model=TokenResponse, summary="Erişim token'ını yenile"
)
def refresh(
    request: Request,
    response: Response,
    settings: WebSettings = Depends(get_settings),
) -> TokenResponse:
    _ensure_user_auth_enabled(settings)
    config = _ensure_jwt_config(settings)

    refresh_cookie = request.cookies.get(settings.refresh_cookie_name)
    if not refresh_cookie:
        raise AuthRequiredError("Yenileme token'ı sunulmadı.")

    # CSRF: header must match the CSRF cookie (double-submit).
    csrf_cookie = request.cookies.get(settings.csrf_cookie_name)
    csrf_header = request.headers.get("X-CSRF-Token")
    if not verify_csrf(csrf_cookie, csrf_header):
        raise AuthForbiddenError("CSRF doğrulaması başarısız oldu.")

    try:
        decoded = decode_token(
            refresh_cookie,
            secret=config.secret,
            algorithm=config.algorithm,
            expected_type=REFRESH_TOKEN_TYPE,
        )
    except TokenError as exc:
        raise AuthRequiredError("Yenileme token'ı geçersiz veya süresi dolmuş.") from exc

    # Re-read the account: role changes / removal apply at the next refresh
    # rather than being copied forward from the token indefinitely, and a
    # changed password ends the session (credential fingerprint mismatch).
    account = account_for_token(settings, decoded)
    if account is None:
        raise AuthRequiredError("Yenileme token'ı geçersiz veya süresi dolmuş.")

    # Single-use rotation: atomically claim this jti. Only the first
    # presentation succeeds; any replay (stolen cookie, concurrent race,
    # already-logged-out token) is rejected. Fail closed if the store is down.
    remaining = max(
        1, int((decoded.expires_at - datetime.now(timezone.utc)).total_seconds())
    )
    try:
        first_use = _denylist(request).consume(decoded.jti, remaining)
    except TokenStoreUnavailable as exc:
        log.error("refresh-denied: revocation store unavailable")
        raise AuthUnavailableError(
            "Kimlik doğrulama geçici olarak kullanılamıyor."
        ) from exc
    if not first_use:
        log.warning(
            "refresh-token-reuse-rejected rid=%s",
            getattr(request.state, "request_id", None),
        )
        raise AuthRequiredError("Yenileme token'ı iptal edilmiş.")

    return _issue_tokens(
        response, settings, config, username=account.username, role=account.role
    )


@router.post("/logout", response_model=LogoutResponse, summary="Kullanıcı çıkışı")
def logout(
    request: Request,
    response: Response,
    settings: WebSettings = Depends(get_settings),
) -> LogoutResponse:
    _ensure_user_auth_enabled(settings)

    # Logout is best-effort: we always clear cookies, even if the refresh
    # token is unparseable. CSRF is still enforced so an attacker cannot
    # force-logout a victim.
    csrf_cookie = request.cookies.get(settings.csrf_cookie_name)
    csrf_header = request.headers.get("X-CSRF-Token")
    if not verify_csrf(csrf_cookie, csrf_header):
        raise AuthForbiddenError("CSRF doğrulaması başarısız oldu.")

    refresh_cookie = request.cookies.get(settings.refresh_cookie_name)
    try:
        config = resolve_jwt_config(settings)
    except AuthConfigError:
        # Misconfigured: no token minted under this config can be trusted, so
        # there is nothing meaningful to revoke. Still clear the cookies.
        config = None
    if refresh_cookie and config is not None:
        try:
            decoded = decode_token(
                refresh_cookie,
                secret=config.secret,
                algorithm=config.algorithm,
                expected_type=REFRESH_TOKEN_TYPE,
            )
            ttl = settings.refresh_token_ttl_days * 24 * 3600
            _denylist(request).revoke(decoded.jti, ttl)
        except TokenError:
            # Already invalid — nothing to revoke. Still clear the cookie.
            pass

    _clear_auth_cookies(response, settings)
    return LogoutResponse(logged_out=True)


@router.get("/me", response_model=UserInfo, summary="Mevcut doğrulanmış kullanıcı")
def me(
    request: Request,
    settings: WebSettings = Depends(get_settings),
) -> UserInfo:
    _ensure_user_auth_enabled(settings)
    user = require_user(request, settings)
    return UserInfo(username=user.username, role=user.role)
