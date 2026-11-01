"""API-layer security utilities (API key auth, user JWT auth, policies)."""

from .auth import (
    AuthError,
    AuthForbiddenError,
    AuthRequiredError,
    AuthUnavailableError,
    Principal,
    compare_api_key,
    match_api_key,
)
from .csrf import create_csrf_token, verify_csrf
from .jwt_tokens import (
    ACCESS_TOKEN_TYPE,
    REFRESH_TOKEN_TYPE,
    DecodedToken,
    TokenError,
    create_access_token,
    create_refresh_token,
    decode_token,
    validate_token_type,
)
from .password import hash_password, verify_password
from .policies import optional_api_key, require_admin_api_key, require_api_key
from .token_store import (
    InMemoryTokenDenylist,
    RedisTokenDenylist,
    TokenDenylist,
    build_token_denylist,
)
from .user_auth import (
    AuthConfigError,
    AuthenticatedUser,
    assert_jwt_secret_usable,
    authenticate_bootstrap_user,
    get_current_user,
    is_strong_jwt_secret,
    require_admin_api_key_or_admin_user,
    require_admin_user,
    require_api_key_or_user,
    require_user,
)

__all__ = [
    "AuthError",
    "AuthRequiredError",
    "AuthForbiddenError",
    "AuthUnavailableError",
    "Principal",
    "compare_api_key",
    "match_api_key",
    "require_api_key",
    "require_admin_api_key",
    "optional_api_key",
    # csrf
    "create_csrf_token",
    "verify_csrf",
    # jwt
    "ACCESS_TOKEN_TYPE",
    "REFRESH_TOKEN_TYPE",
    "DecodedToken",
    "TokenError",
    "create_access_token",
    "create_refresh_token",
    "decode_token",
    "validate_token_type",
    # password
    "hash_password",
    "verify_password",
    # token store
    "TokenDenylist",
    "InMemoryTokenDenylist",
    "RedisTokenDenylist",
    "build_token_denylist",
    # user auth
    "AuthConfigError",
    "AuthenticatedUser",
    "assert_jwt_secret_usable",
    "authenticate_bootstrap_user",
    "get_current_user",
    "is_strong_jwt_secret",
    "require_user",
    "require_admin_user",
    "require_api_key_or_user",
    "require_admin_api_key_or_admin_user",
]
