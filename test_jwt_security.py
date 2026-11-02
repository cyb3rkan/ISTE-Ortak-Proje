"""
JWT güvenlik testleri — algorithm confusion ve token replay saldırılarına karşı.
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

import jwt
import pytest

from ioc_enricher.web.api.security.jwt_tokens import (
    ACCESS_TOKEN_TYPE,
    REFRESH_TOKEN_TYPE,
    TokenError,
    create_access_token,
    create_refresh_token,
    decode_token,
)


SECRET = "test-secret-key-minimum-32-characters-long!!"
ALT_SECRET = "different-secret-key-minimum-32-char-alt!!"


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


class TestJWTAlgorithmConfusion:
    def test_none_algorithm_rejected(self):
        """'none' algoritmasıyla üretilen token reddedilmeli."""
        now = datetime.now(tz=timezone.utc)
        payload = {
            "sub": "admin",
            "role": "admin",
            "type": ACCESS_TOKEN_TYPE,
            "jti": "test",
            "iss": "ioc-enricher",
            "exp": int((now + timedelta(minutes=10)).timestamp()),
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
        }
        # 'none' algoritmasıyla manuel token üret
        none_token = jwt.encode(payload, key="", algorithm="none")
        with pytest.raises(TokenError):
            decode_token(
                none_token,
                secret=SECRET,
                algorithm="HS256",
                expected_type=ACCESS_TOKEN_TYPE,
            )

    def test_wrong_secret_rejected(self):
        """Farklı secret ile imzalanmış token reddedilmeli."""
        token, _ = create_access_token(
            subject="user",
            role="analyst",
            secret=ALT_SECRET,
            algorithm="HS256",
        )
        with pytest.raises(TokenError):
            decode_token(
                token,
                secret=SECRET,
                algorithm="HS256",
                expected_type=ACCESS_TOKEN_TYPE,
            )

    def test_access_token_not_usable_as_refresh(self):
        """Access token refresh endpoint'inde kullanılamamalı."""
        token, _ = create_access_token(
            subject="admin", role="admin", secret=SECRET
        )
        with pytest.raises(TokenError):
            decode_token(
                token,
                secret=SECRET,
                algorithm="HS256",
                expected_type=REFRESH_TOKEN_TYPE,
            )

    def test_refresh_token_not_usable_as_access(self):
        """Refresh token access endpoint'inde kullanılamamalı."""
        token, _ = create_refresh_token(
            subject="admin", role="admin", secret=SECRET
        )
        with pytest.raises(TokenError):
            decode_token(
                token,
                secret=SECRET,
                algorithm="HS256",
                expected_type=ACCESS_TOKEN_TYPE,
            )

    def test_expired_token_rejected(self):
        """Süresi dolmuş token reddedilmeli (diğer tüm claim'ler geçerli)."""
        now = datetime.now(tz=timezone.utc)
        expired_payload = {
            "sub": "admin",
            "role": "admin",
            "type": ACCESS_TOKEN_TYPE,
            "jti": "expired-jti",
            "iss": "ioc-enricher",
            "aud": "ioc-enricher-api",
            "exp": int((now - timedelta(minutes=5)).timestamp()),
            "iat": int((now - timedelta(minutes=10)).timestamp()),
            "nbf": int((now - timedelta(minutes=10)).timestamp()),
        }
        expired_token = jwt.encode(expired_payload, SECRET, algorithm="HS256")
        with pytest.raises(TokenError, match="expired"):
            decode_token(
                expired_token,
                secret=SECRET,
                algorithm="HS256",
                expected_type=ACCESS_TOKEN_TYPE,
            )

    def test_tampered_payload_rejected(self):
        """Payload'ı değiştirilmiş token reddedilmeli."""
        token, _ = create_access_token(
            subject="analyst", role="analyst", secret=SECRET
        )
        # Token'ı parse et, payload'ı değiştir, tekrar birleştir (imza bozulur)
        header_b64, payload_b64, sig_b64 = token.split(".")
        payload = json.loads(_b64url_decode(payload_b64))
        payload["role"] = "admin"  # Privilege escalation dene
        tampered_payload_b64 = _b64url_encode(
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
        )
        tampered_token = f"{header_b64}.{tampered_payload_b64}.{sig_b64}"
        with pytest.raises(TokenError):
            decode_token(
                tampered_token,
                secret=SECRET,
                algorithm="HS256",
                expected_type=ACCESS_TOKEN_TYPE,
            )

    def test_empty_secret_raises(self):
        """Boş secret ile decode reddedilmeli."""
        token, _ = create_access_token(
            subject="admin", role="admin", secret=SECRET
        )
        with pytest.raises(TokenError):
            decode_token(
                token,
                secret="",
                algorithm="HS256",
                expected_type=ACCESS_TOKEN_TYPE,
            )
