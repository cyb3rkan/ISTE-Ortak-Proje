"""
Centralised configuration loaded entirely from environment variables.

Usage:
    from ioc_enricher.utils.config import Config

    key = Config.VIRUSTOTAL_API_KEY   # str, may be ""
    Config.create_directories()       # idempotent setup
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Dict, List, MutableMapping, Optional

from dotenv import dotenv_values

DOTENV_ENV_VAR = "IOC_ENRICHER_DOTENV"
_DOTENV_DISABLED = frozenset({"0", "false", "off", "no", "none"})


def load_env_file(
    environ: Optional[MutableMapping[str, str]] = None,
    cwd: Optional[Path] = None,
) -> Optional[Path]:
    """
    Load a development ``.env`` file explicitly and predictably.

    * ``IOC_ENRICHER_DOTENV`` unset -> ``<cwd>/.env`` only (parent directories
      are never searched, so an installed package cannot pick up an unrelated
      ``.env`` higher up the filesystem).
    * ``IOC_ENRICHER_DOTENV=<path>`` -> exactly that file.
    * ``IOC_ENRICHER_DOTENV=0|false|off|no|none`` -> nothing is loaded.

    Variables already present in the environment always win, so Docker / CI /
    shell-provided values are never overridden. Values are never logged.
    Returns the file that was loaded, or ``None``.
    """
    env = os.environ if environ is None else environ
    setting = env.get(DOTENV_ENV_VAR, "").strip()
    if setting.lower() in _DOTENV_DISABLED and setting:
        return None
    if setting:
        path = Path(setting).expanduser()
        if not path.is_file():
            print(
                f"warning: {DOTENV_ENV_VAR} points to a missing file: {path}",
                file=sys.stderr,
            )
            return None
    else:
        path = (cwd or Path.cwd()) / ".env"
        if not path.is_file():
            return None

    for key, value in dotenv_values(path).items():
        if value is not None and key not in env:
            env[key] = value
    return path


# Config reads the environment at class-definition time, so the optional
# development .env must be applied before the class body below runs.
load_env_file()


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    """An integer setting clamped to ``[minimum, maximum]``; unparsable -> *default*."""
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        return default
    return min(max(value, minimum), maximum)


def _env_float(name: str, default: float, minimum: float, maximum: float) -> float:
    """A numeric setting clamped to ``[minimum, maximum]``; unparsable -> *default*."""
    try:
        value = float(os.getenv(name, str(default)))
    except ValueError:
        return default
    if value != value:  # NaN
        return default
    return min(max(value, minimum), maximum)


def _env_dir(name: str, default: Path) -> Path:
    """A directory setting; unset or blank -> *default*. Nothing is created here."""
    value = os.getenv(name, "").strip()
    return Path(value).expanduser() if value else default


class Config:
    """
    Application-wide configuration.

    All values are read from environment variables.  No defaults contain
    secrets; missing API keys result in the corresponding provider being
    disabled rather than a hard crash.
    """

    # ------------------------------------------------------------------
    # Paths
    # ------------------------------------------------------------------
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent
    # IOC_ENRICHER_DATA_DIR / IOC_ENRICHER_REPORTS_DIR move the runtime data
    # (e.g. onto container volumes); the cache always lives in DATA_DIR/cache.
    DATA_DIR: Path = _env_dir("IOC_ENRICHER_DATA_DIR", BASE_DIR / "data")
    CACHE_DIR: Path = DATA_DIR / "cache"
    REPORTS_DIR: Path = _env_dir("IOC_ENRICHER_REPORTS_DIR", BASE_DIR / "reports")
    LOGS_DIR: Path = BASE_DIR / "logs"

    # ------------------------------------------------------------------
    # Provider API keys  (empty string == provider disabled)
    # ------------------------------------------------------------------
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    SHODAN_API_KEY: str = os.getenv("SHODAN_API_KEY", "")
    OTX_API_KEY: str = os.getenv("OTX_API_KEY", "")
    GREYNOISE_API_KEY: str = os.getenv("GREYNOISE_API_KEY", "")
    ZEROBOUNCE_API_KEY: str = os.getenv("ZEROBOUNCE_API_KEY", "")

    # ------------------------------------------------------------------
    # AI analysis (optional) — Groq only
    #
    # The AI layer is a Groq-backed narrative on top of the deterministic
    # score. It NEVER alters the risk score.
    #
    # Provider selection:
    #   * AI_PROVIDER=groq      -> Groq chat completions
    #   * AI_PROVIDER=disabled  -> AI layer off regardless of keys
    #   * AI_PROVIDER unset     -> Groq is auto-enabled when GROQ_API_KEY is set
    #
    # Only "groq" and "disabled" are accepted. Any other value (including a
    # legacy "openai") is treated as unset and falls back to key-based
    # auto-detection — there is no OpenAI code path.
    # ------------------------------------------------------------------
    AI_PROVIDER: str = os.getenv("AI_PROVIDER", "").strip().lower()

    # --- Groq (OpenAI-compatible HTTP API) ---
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    GROQ_BASE_URL: str = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
    GROQ_MODEL: str = os.getenv("GROQ_MODEL", "openai/gpt-oss-20b")
    GROQ_MAX_TOKENS: int = int(os.getenv("GROQ_MAX_TOKENS", "1200"))
    GROQ_TEMPERATURE: float = float(os.getenv("GROQ_TEMPERATURE", "0.2"))
    GROQ_TIMEOUT_SECONDS: int = int(os.getenv("GROQ_TIMEOUT_SECONDS", "30"))

    # ------------------------------------------------------------------
    # Caching
    # ------------------------------------------------------------------
    ENABLE_CACHE: bool = os.getenv("ENABLE_CACHE", "true").lower() == "true"
    CACHE_TTL_HOURS: int = int(os.getenv("CACHE_TTL_HOURS", "24"))
    # Upper bound of the cache directory; the oldest entries go first.
    CACHE_MAX_SIZE_MB: int = _env_int("CACHE_MAX_SIZE_MB", 100, 1, 100_000)

    # ------------------------------------------------------------------
    # Web report retention (reports/web)
    # ------------------------------------------------------------------
    REPORT_RETENTION_DAYS: int = _env_int("REPORT_RETENTION_DAYS", 30, 1, 3650)
    REPORT_MAX_TOTAL_MB: int = _env_int("REPORT_MAX_TOTAL_MB", 200, 1, 100_000)

    # ------------------------------------------------------------------
    # HTTP / concurrency
    # ------------------------------------------------------------------
    REQUEST_TIMEOUT: int = int(os.getenv("REQUEST_TIMEOUT", "30"))
    # Provider calls in flight at once, shared by every enrichment of one
    # enricher (one bounded worker pool, not one pool per IOC).
    MAX_CONCURRENT_REQUESTS: int = int(os.getenv("MAX_CONCURRENT_REQUESTS", "5"))
    # Time budget for one IOC's provider phase. Providers still unanswered
    # at the deadline are reported as "timeout"; finished ones are kept.
    # 0 disables the deadline.
    IOC_DEADLINE_SECONDS: float = _env_float("IOC_DEADLINE_SECONDS", 60.0, 0.0, 600.0)
    # Longest a provider call waits for a rate-limit slot; a longer wait
    # (e.g. during an HTTP 429 pause) answers "rate_limited" at once instead
    # of pinning a worker.
    RATE_LIMIT_MAX_WAIT_SECONDS: float = _env_float("RATE_LIMIT_MAX_WAIT_SECONDS", 20.0, 0.0, 300.0)
    # Per-minute pacing overrides, "Name=requests_per_minute[:burst];...",
    # e.g. "VirusTotal=500:10;GreyNoise=30:5". Empty keeps the built-in
    # defaults (see utils/rate_limiter.py).
    PROVIDER_RATE_LIMITS: str = os.getenv("PROVIDER_RATE_LIMITS", "")

    # ------------------------------------------------------------------
    # Risk score thresholds (configurable via env)
    # ------------------------------------------------------------------
    SCORE_LOW_MAX: int = int(os.getenv("SCORE_LOW_MAX", "20"))
    SCORE_MEDIUM_MAX: int = int(os.getenv("SCORE_MEDIUM_MAX", "50"))
    SCORE_HIGH_MAX: int = int(os.getenv("SCORE_HIGH_MAX", "80"))
    # Scores above SCORE_HIGH_MAX are CRITICAL

    # Human review is flagged when score falls in this ambiguous range
    HUMAN_REVIEW_MIN: int = int(os.getenv("HUMAN_REVIEW_MIN", "35"))
    HUMAN_REVIEW_MAX: int = int(os.getenv("HUMAN_REVIEW_MAX", "65"))

    # ------------------------------------------------------------------
    # Secure redaction (applied before sending data to AI)
    # ------------------------------------------------------------------
    REDACT_BEFORE_AI: bool = os.getenv("REDACT_BEFORE_AI", "true").lower() == "true"
    # Comma-separated list of field names whose values are masked
    REDACT_FIELDS: str = os.getenv(
        "REDACT_FIELDS",
        "email,token,api_key,apikey,groq_api_key,authorization,bearer,"
        "internal_ip,hostname,username,path",
    )
    # Field lengths sent to the AI are fixed per field class in
    # core/analyzer.py (facts 64, quoted text 120, IOC 256, reasons 300).

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()
    # Empty disables the file log (console only).
    LOG_FILE: str = os.getenv("LOG_FILE", "logs/ioc_enricher.log")
    # Rotating file log: at most LOG_MAX_BYTES per file, LOG_BACKUP_COUNT backups.
    LOG_MAX_BYTES: int = _env_int("LOG_MAX_BYTES", 10 * 1024 * 1024, 64 * 1024, 1024 ** 3)
    LOG_BACKUP_COUNT: int = _env_int("LOG_BACKUP_COUNT", 5, 0, 20)

    # ------------------------------------------------------------------
    # Class helpers
    # ------------------------------------------------------------------

    @classmethod
    def create_directories(cls) -> List[str]:
        """
        Create the runtime directories (idempotent). Called by the CLI and the
        web server at start-up — never on import. A directory created here is
        owner-only (POSIX).

        Returns:
            The settings whose directory could not be created (names only:
            paths are not echoed). Never raises.
        """
        failed: List[str] = []
        for name in ("DATA_DIR", "CACHE_DIR", "REPORTS_DIR", "LOGS_DIR"):
            try:
                Path(getattr(cls, name)).mkdir(mode=0o700, parents=True, exist_ok=True)
            except OSError:
                failed.append(name)
        return failed

    @classmethod
    def resolve_ai_provider(cls) -> str:
        """
        Resolve the effective AI provider name. Only Groq is supported.

        Resolution rules:
            * AI_PROVIDER=disabled               -> "disabled"
            * AI_PROVIDER=groq                   -> "groq"
            * AI_PROVIDER unset, GROQ_API_KEY set -> "groq" (auto-enabled)
            * anything else (no key / unknown)   -> "disabled"

        An unrecognised ``AI_PROVIDER`` value — including a legacy "openai" —
        is treated as unset: it never selects a non-Groq backend. This only
        names the provider; key validation happens in :meth:`ai_credentials`.
        """
        provider = cls.AI_PROVIDER
        if provider == "disabled":
            return "disabled"
        if provider == "groq":
            return "groq"
        # Unset / unrecognised -> auto-enable Groq only when its key is present.
        if cls.GROQ_API_KEY:
            return "groq"
        return "disabled"

    @classmethod
    def ai_credentials(cls) -> Dict[str, object]:
        """
        Return the resolved Groq client settings.

        Keys: provider, api_key, base_url, model, max_tokens, temperature,
        timeout. ``api_key`` is "" when the provider is disabled or its key is
        missing — callers treat an empty key as "AI layer off" (no hard
        crash). Never log the returned ``api_key``.
        """
        provider = cls.resolve_ai_provider()
        if provider == "groq":
            return {
                "provider": "groq",
                "api_key": cls.GROQ_API_KEY,
                "base_url": cls.GROQ_BASE_URL,
                "model": cls.GROQ_MODEL,
                "max_tokens": cls.GROQ_MAX_TOKENS,
                "temperature": cls.GROQ_TEMPERATURE,
                "timeout": cls.GROQ_TIMEOUT_SECONDS,
            }
        return {
            "provider": "disabled",
            "api_key": "",
            "base_url": None,
            "model": "",
            "max_tokens": 0,
            "temperature": 0.0,
            "timeout": 0,
        }

    @classmethod
    def ai_enabled(cls) -> bool:
        """True when an AI provider is selected AND its API key is present."""
        creds = cls.ai_credentials()
        return creds["provider"] != "disabled" and bool(creds["api_key"])

    @classmethod
    def provider_status(cls) -> Dict[str, bool]:
        """Return a mapping of provider name → whether its API key is set."""
        # The AI layer is Groq-only; it is labelled as such regardless of
        # whether it is currently enabled.
        return {
            "VirusTotal": bool(cls.VIRUSTOTAL_API_KEY),
            "AbuseIPDB": bool(cls.ABUSEIPDB_API_KEY),
            "Shodan": bool(cls.SHODAN_API_KEY),
            "AlienVault OTX": bool(cls.OTX_API_KEY),
            "GreyNoise": bool(cls.GREYNOISE_API_KEY),
            "ZeroBounce": bool(cls.ZEROBOUNCE_API_KEY),
            "Groq (AI layer)": cls.ai_enabled(),
        }

    @classmethod
    def validate(cls) -> list[str]:
        """
        Return a list of configuration warnings.

        The tool can still run if warnings exist — some providers will
        simply be skipped.  This method never raises.
        """
        warnings: list[str] = []
        if not any([
            cls.VIRUSTOTAL_API_KEY,
            cls.ABUSEIPDB_API_KEY,
            cls.SHODAN_API_KEY,
            cls.OTX_API_KEY,
            cls.GREYNOISE_API_KEY,
            cls.ZEROBOUNCE_API_KEY,
        ]):
            warnings.append(
                "No threat intelligence provider API keys configured. "
                "Set at least one key in your .env file."
            )
        return warnings
