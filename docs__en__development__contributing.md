# Development & Contributing

## 1. Overview

This document describes the development setup, the project layout, how to add
a provider, and the testing and security rules for contributions to IOC
Enricher.

---

## 2. Development Environment Setup

### Prerequisites

- Python 3.11+ (CI and the backend image use 3.12)
- Node.js 24 and npm for the frontend
- Git

### Setup

```bash
# Clone the repository
git clone https://github.com/your-org/ioc-enricher-agent.git
cd ioc-enricher-agent

# Create virtual environment
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
.venv\Scripts\activate      # Windows

# Install the hash-pinned test lock and the package (editable)
python -m pip install -r requirements.txt
python -m pip install --no-deps -e .

# Configure environment (optional for tests)
cp .env.example .env
# Edit .env — add a provider API key only for manual testing

# Frontend
cd frontend && npm ci && cd ..
```

### Verify Setup

```bash
# Backend test suite (no API keys needed)
python -m pytest tests ioc_enricher/tests -q

# Check provider status (no network request)
python -m ioc_enricher --status

# Enrich a documentation IOC (sent to configured providers, if any)
python -m ioc_enricher --ip 203.0.113.7
```

Without the editable install, `pytest` and `python -m pytest` work from the
repository root for runs that include `tests/` (its `conftest.py` adds the
package path); for `ioc_enricher/tests` alone use plain `pytest` or set
`PYTHONPATH=ioc_enricher`.

---

## 3. Project Structure

```
ioc_enricher/
├── ioc_enricher/           # Main Python package
│   ├── __init__.py         # Public API exports (IOCEnricher)
│   ├── __main__.py         # python -m ioc_enricher entry point
│   ├── enricher.py         # Pipeline orchestrator (IOCEnricher)
│   ├── core/               # validator, aggregator, scoring, analyzer (AI), eicar
│   ├── providers/          # base.py, _fields.py (parsing helpers), six providers
│   ├── models/             # ioc.py, result.py
│   ├── mitre/              # mapper.py
│   ├── reports/            # generator.py
│   ├── utils/              # config, logger, cache, rate_limiter, fileio
│   ├── web/                # service, schemas (DTOs), mappers, report_store, settings,
│   │                       # api/ (FastAPI app, middleware, routers, security)
│   └── cli/                # main.py
└── tests/                  # package unit tests
tests/                      # adapter, api, cli, security tests (+ integration server)
frontend/                   # React app, Vitest tests, Playwright E2E
```

---

## 4. Adding a New Provider

### Step 1 — Create the provider module

```python
# providers/new_provider.py
from typing import Dict, FrozenSet

from ..models import IOCType, ProviderResult
from ._fields import count, text
from .base import BaseProvider


class NewProvider(BaseProvider):
    BASE_URL = "https://api.newprovider.example"   # fixed, MUST be HTTPS
    SUPPORTED_IOC_TYPES: FrozenSet[IOCType] = frozenset({IOCType.IPV4, IOCType.IPV6})

    @property
    def name(self) -> str:
        return "NewProvider"            # also the rate-limiter bucket name

    def _get_headers(self) -> Dict[str, str]:
        return {"X-Api-Key": self._api_key, "Accept": "application/json"}

    def lookup_ip(self, ip: str) -> ProviderResult:
        result = self._request("GET", f"{self.BASE_URL}/ip/{ip}")
        if not result.is_success():
            return result               # error / timeout / rate_limited, already explained
        raw = result.data
        if not isinstance(raw, dict):
            return self._invalid(result, "body is not an object")
        result.data = {
            "threat_score": count(raw.get("score")),      # None when absent or mistyped
            "category": text(raw.get("category"), 64),
        }
        return result
```

- The constructor is inherited: `BaseProvider(api_key, timeout=30,
  rate_limiter=None)`.
- `_request(method, url, *, params=None, json_body=None)` returns a
  `ProviderResult`; it enforces HTTPS, the rate limit, the per-IOC deadline,
  retries and the circuit breaker. Never call `requests` directly.
- Do not implement lookups for unsupported types: the base class returns an
  `unsupported` result.
- Parse defensively with the `_fields` helpers (`text`, `flag`, `count`,
  `text_list`): an absent or mistyped value becomes `None`, never `0` or
  `False`. Percent-encode IOC values placed in a URL path.

### Step 2 — Configuration

Add `NEW_PROVIDER_API_KEY` to `utils/config.py` (and to `provider_status()`),
and an empty `NEW_PROVIDER_API_KEY=` line to `.env.example`
(`tests/security/test_example_config.py` requires secrets to stay empty).

### Step 3 — Instantiate in `IOCEnricher`

Add `(cfg.NEW_PROVIDER_API_KEY, NewProvider)` to the `candidates` list in
`IOCEnricher._init_providers()`; providers without a key are not created.

### Step 4 — Rate limit

Add `"NewProvider": (rpm, burst)` to `_PROVIDER_LIMITS` in
`utils/rate_limiter.py`; otherwise the `_default` bucket (30/min, burst 5)
applies. Operators can override it with `PROVIDER_RATE_LIMITS`.

### Step 5 — Scoring

Add a capped `_score_new_provider(...)` contribution in `core/scoring.py` and a
field in `ScoreBreakdown` (`models/result.py`). Keep the evidence semantics:
`not_found` means "no evidence", and an unavailable provider must appear in
`unavailable_providers`, never as a clean answer.

### Step 6 — Web API and AI allow-lists

- `web/mappers.py` `_PROVIDER_SAFE_FIELDS`: list the fields the API may
  return. An unlisted provider is shown only as `available_fields` (names,
  no values). Mirror new fields in `frontend/src/types/api.ts` if the UI
  uses them.
- `core/analyzer.py` `_AI_PROVIDER_FIELDS`: list only structured,
  non-sensitive facts the AI layer may see. Without an entry nothing from the
  provider reaches the model; free text must go through the quoted
  untrusted-text path.

### Step 7 — Write Tests

```python
# ioc_enricher/tests/test_providers.py
from unittest.mock import MagicMock

def test_new_provider_parsing():
    provider = NewProvider(api_key="fake-test-key")
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"score": 75, "category": "scanner"}
    resp.text = str(resp.json.return_value)
    provider._session.request = MagicMock(return_value=resp)   # no real HTTP
    result = provider.lookup_ip("203.0.113.7")
    assert result.is_success()
    assert result.data["threat_score"] == 75
```

Copy the response stub from the existing `_mock_response()` helper in
`ioc_enricher/tests/test_providers.py`, and add contract cases to
`tests/adapter/test_api_contract.py` and limit cases to
`ioc_enricher/tests/test_provider_limits.py` where relevant.

### Step 8 — Documentation

Add `docs/en/providers/<name>.md` and `docs/tr/providers/<name>.md`, and
update the provider overview, the README tables and `.env.example`.

---

## 5. Code Style

- **Python version:** 3.11+
- **Formatting:** Follow PEP 8.
- **Type hints:** All public function signatures must include type hints.
- **Dataclasses:** Value objects are dataclasses (`IOC` is frozen).
- **Error handling:** Never let exceptions propagate from provider
  `lookup_*()` methods — return a `ProviderResult` with an explicit status.
- **Logging:** Use `get_logger(__name__)` from `utils/logger.py` — never
  `print()` for diagnostics; refer to IOCs with `ioc_ref()`, not their value.
- **No hardcoded secrets:** API keys only from environment variables.

---

## 6. Testing Requirements

- All new code must include tests; a bug fix includes a test that fails
  before the fix.
- Tests must not make real HTTP calls and must not require API keys.
- Run the CI command before submitting a pull request:

```bash
python -m pytest ioc_enricher/tests tests/adapter tests/cli tests/api tests/security \
  --cov=ioc_enricher --cov-report=term-missing --cov-fail-under=80 -q
cd frontend && npm run test && npm run build
```

CI fails below 80 % coverage; do not lower coverage with a change.

---

## 7. Commit & Pull Request Guidelines

- Use conventional commit format: `feat:`, `fix:`, `test:`, `docs:`, `refactor:`
- Each PR should address one concern (one feature, one bug, one provider).
- Include a test for every bug fix — the test should fail before the fix and pass after.
- Update documentation in `docs/` (English and Turkish) for any new feature or provider.
- Update `SECURITY.md` if your change has security implications.
- Do not change the dependency locks by hand; regenerate them as described in
  `requirements.txt`.

---

## 8. Security Guidelines for Contributors

- Never log API keys or tokens. The logger's masking is a safety net, not a
  licence to log secrets.
- Never accept provider base URLs from user configuration — hardcode HTTPS
  provider endpoints.
- Always use `BaseProvider._request()` for HTTP calls.
- Always parse provider responses defensively (`_fields` helpers, type
  checks); treat every provider string as untrusted text.
- Never render provider, AI or report text as HTML in the frontend
  (`dangerouslySetInnerHTML` is banned and checked in CI).
- Run Bandit as CI does, from the locked tools file:

```bash
python -m pip install --require-hashes -r requirements/tools.txt
bandit -r ioc_enricher/ioc_enricher --exclude ioc_enricher/ioc_enricher/tests \
  --severity-level medium --confidence-level medium
```

CI also runs a blocking `pip-audit --strict` over the locks and
`npm audit --audit-level=low`; both need network access.

---

## 9. Related Documents

- [Architecture Overview](../architecture/overview.md)
- [Provider Overview](../providers/overview.md)
- [Security Considerations](../security/considerations.md)
- [Test Documentation](../tests/test_providers.md)
