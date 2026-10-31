"""
Browser-integration test server: the REAL FastAPI app with a FAKE enricher.

Used by ``frontend/playwright.integration.config.ts``. Everything security
relevant is real — JWT login, httpOnly refresh cookie, CSRF double-submit,
single-use refresh rotation, logout revocation, rate limiting, report store —
while enrichment is served by an in-process fake so no provider or AI API is
ever contacted (no network, no paid calls, no API keys).

Run:  python tests/integration/e2e_server.py  [--port 8765]
"""
from __future__ import annotations

import argparse
import asyncio
import os
import secrets
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

# Configuration comes only from this file — never from a developer's .env.
os.environ["IOC_ENRICHER_DOTENV"] = "0"
# Console log only: the default LOG_FILE (logs/ioc_enricher.log under the
# working directory) would put a runtime log into frontend/.
os.environ["LOG_FILE"] = ""

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "ioc_enricher"))

import uvicorn  # noqa: E402

from ioc_enricher.core.analyzer import AIAnalyzer  # noqa: E402
from ioc_enricher.core.scoring import RiskScorer  # noqa: E402
from ioc_enricher.core.validator import IOCValidator  # noqa: E402
from ioc_enricher.mitre.mapper import MITREMapper  # noqa: E402
from ioc_enricher.models.result import (  # noqa: E402
    EnrichmentResult,
    MITREEntry,
    ProviderResult,
    ProviderStatus,
    RiskLevel,
    RiskScore,
    ScoreBreakdown,
)
from ioc_enricher.web.api.app import create_app  # noqa: E402
from ioc_enricher.web.api.deps import get_enrichment_service  # noqa: E402
from ioc_enricher.web.api.security.password import hash_password  # noqa: E402
from ioc_enricher.web.report_store import ReportStore  # noqa: E402
from ioc_enricher.web.service import EnrichmentService  # noqa: E402
from ioc_enricher.web.settings import WebSettings  # noqa: E402

# Fixed, test-only credentials (shared with the Playwright spec).
E2E_USERNAME = "e2e-admin"
E2E_PASSWORD = "E2E-Integration-Pass-1!"


class _FakeCache:
    def stats(self):
        return {"entry_count": 0, "total_size_kb": 0.0, "ttl_hours": 24.0, "enabled": True}

    def clear(self) -> int:
        return 0


class _FakeAI:
    enabled = False


class FakeEnricher:
    """Deterministic, offline stand-in for IOCEnricher."""

    def __init__(self) -> None:
        self._cache = _FakeCache()
        self._ai = _FakeAI()

    def provider_status(self):
        return {"VirusTotal": True}

    def enrich(self, raw_ioc: str, save_report=None, use_cache: bool = True):
        ioc, error = IOCValidator.validate(raw_ioc.strip())
        if error or ioc is None:
            raise ValueError(error or "Invalid IOC.")
        if ioc.value in _SCORED_FIXTURES:
            return self._scored(ioc, save_report)
        bad = ioc.value.startswith("evil")
        return EnrichmentResult(
            ioc=ioc.value,
            ioc_type=ioc.ioc_type,
            provider_results={
                "VirusTotal": ProviderResult(
                    "VirusTotal",
                    ProviderStatus.SUCCESS,
                    {"malicious": 40 if bad else 0, "harmless": 30},
                    response_time=0.05,
                )
            },
            risk_score=RiskScore(
                score=85 if bad else 10,
                level=RiskLevel.CRITICAL if bad else RiskLevel.LOW,
                breakdown=ScoreBreakdown(virustotal=85 if bad else 10),
                reasons=["40 engines flag it"] if bad else ["No malicious detections"],
                detection_confidence=0.9,
            ),
            mitre_mappings=[
                MITREEntry("Command and Control", "T1071", "Application Layer Protocol", "C2")
            ] if bad else [],
            ai_analysis=None,
            execution_time=0.1,
            timestamp=datetime.now(timezone.utc),
        )

    def _scored(self, ioc, save_report=None):
        """Fixture provider data → REAL scorer, MITRE mapper and offline AI
        fallback (no network). Exercises the scoring/DTO path end to end."""
        provider_results = _SCORED_FIXTURES[ioc.value]()
        risk = RiskScorer().score(
            provider_results, ioc_value=ioc.value, ioc_type=ioc.ioc_type
        )
        return EnrichmentResult(
            ioc=ioc.value,
            ioc_type=ioc.ioc_type,
            provider_results=provider_results,
            risk_score=risk,
            mitre_mappings=MITREMapper().map(ioc.ioc_type, provider_results),
            ai_analysis=AIAnalyzer(enabled=False).offline_analysis(
                risk, ioc_type=ioc.ioc_type
            ),
            execution_time=0.1,
            timestamp=datetime.now(timezone.utc),
        )


def _ok(name: str, data: dict) -> ProviderResult:
    return ProviderResult(name, ProviderStatus.SUCCESS, data, response_time=0.05)


# Deterministic provider payloads mirroring live observations (scoring audit).
_SCORED_FIXTURES = {
    # Tor exit node: AbuseIPDB 100% / Tor, VT 13/92, OTX 50, Shodan HTTP 403.
    "185.220.101.1": lambda: {
        "AbuseIPDB": _ok("AbuseIPDB", {
            "abuse_confidence_score": 100, "total_reports": 409, "is_tor": True,
        }),
        "VirusTotal": _ok("VirusTotal", {
            "malicious_count": 13, "suspicious_count": 4, "total_engines": 92,
        }),
        "AlienVault OTX": _ok("AlienVault OTX", {"pulse_count": 50}),
        "GreyNoise": _ok("GreyNoise", {
            "classification": "unknown", "noise": False, "riot": False,
        }),
        "Shodan": ProviderResult(
            "Shodan", ProviderStatus.ERROR, error="HTTP 403", response_time=0.05
        ),
    },
    # Generic URL: VT 0/93 (63 harmless), 17 OTX pulses — previously 35 MEDIUM.
    "https://example.com/": lambda: {
        "VirusTotal": _ok("VirusTotal", {
            "malicious_count": 0, "suspicious_count": 0, "harmless_count": 63,
            "total_engines": 93, "reputation": -346,
        }),
        "AlienVault OTX": _ok("AlienVault OTX", {"pulse_count": 17}),
    },
    # Email with no provider answer at all.
    "security@example.com": lambda: {},
}


def _add_refresh_response_delay(app, delay_ms: int) -> None:
    """
    TEST-ONLY: hold POST /auth/refresh responses for *delay_ms* AFTER the
    handler has run (token already consumed + successor minted). This opens a
    deterministic window in which a page reload / second tab races an
    in-flight refresh — the condition behind the rapid-reload logout bug.
    """
    if delay_ms <= 0:
        return

    @app.middleware("http")
    async def _delay(request, call_next):
        response = await call_next(request)
        if request.method == "POST" and request.url.path.endswith("/auth/refresh"):
            await asyncio.sleep(delay_ms / 1000)
        return response


def build_app(frontend_origin: str, refresh_delay_ms: int = 0):
    settings = WebSettings(
        debug=False,
        enable_docs=False,
        user_auth_enabled=True,
        jwt_secret_key=secrets.token_urlsafe(48),
        bootstrap_admin_username=E2E_USERNAME,
        bootstrap_admin_password_hash=hash_password(E2E_PASSWORD),
        cors_allowed_origins=[frontend_origin],
        rate_limit_enabled=True,
        login_rate_limit_per_minute=60,
        refresh_rate_limit_per_minute=120,
    )
    app = create_app(settings)
    service = EnrichmentService(
        enricher=FakeEnricher(),
        report_store=ReportStore(base_dir=tempfile.mkdtemp(prefix="ioc-e2e-reports-")),
        batch_deadline_seconds=25,
    )
    app.dependency_overrides[get_enrichment_service] = lambda: service
    _add_refresh_response_delay(app, refresh_delay_ms)
    return app


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--frontend-origin", default="http://127.0.0.1:4175")
    parser.add_argument("--refresh-delay-ms", type=int, default=0)
    args = parser.parse_args()
    uvicorn.run(
        build_app(args.frontend_origin, args.refresh_delay_ms),
        host="127.0.0.1",
        port=args.port,
        log_level="warning",
    )


if __name__ == "__main__":
    main()
