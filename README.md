# 🔍 IOC Enricher Agent

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Completed-success?style=for-the-badge)
![AI](https://img.shields.io/badge/AI-Optional_narrative-blueviolet?style=for-the-badge)

**Threat Intelligence Aggregation & Deterministic Risk Scoring — with an optional AI narrative**

A cybersecurity tool that aggregates data from multiple threat-intelligence providers into a deterministic, evidence-aware risk assessment for Indicators of Compromise (IOCs). An optional AI layer (Groq) adds a narrative on top; it never changes the score or the evidence.

---

## 📦 Package layout (canonical vs. legacy)

The supported, canonical Python package lives under:

```
ioc_enricher/ioc_enricher/
```

After installing the project in editable mode you can run the CLI from the
repository root:

```bash
python -m pip install -r requirements.txt   # hash-pinned lock (requirements/test.txt)
python -m pip install --no-deps -e .         # the package itself
python -m ioc_enricher --version
python -m ioc_enricher --status
python -m ioc_enricher --ioc 203.0.113.7
```

> The canonical package physically lives at `ioc_enricher/ioc_enricher/`; the
> repository's `pyproject.toml` wires that up via `tool.setuptools.package-dir`.
> The test suite also retains a small `sys.path` shim in `tests/conftest.py`
> so a fresh checkout can be tested before the install (see "Running the
> tests").

Programmatic use:

```python
from ioc_enricher import IOCEnricher

result = IOCEnricher().enrich("203.0.113.7")
print(result.risk_score.score, result.risk_score.level.value)
```

> ⚠️ **Legacy notice.** The original prototype that lived under root `src/` and
> was invoked via `python main.py` is now **deprecated** and has been moved
> under [`legacy/`](legacy/README.md). Do not import from `src.*` in new code.

### Web adapter (framework-free service layer)

The framework-free **service layer** lives under `ioc_enricher/ioc_enricher/web/`.
It exposes the enrichment engine through a Python service object with web-safe
Pydantic DTOs, sanitised provider summaries and UUID-based report storage:

```python
from ioc_enricher.web.service import EnrichmentService
from ioc_enricher.web.schemas import EnrichRequest

dto = EnrichmentService().enrich_single(EnrichRequest(ioc="203.0.113.7"))
```

This service has **no FastAPI / auth / database** dependency of its own; it is
deliberately reusable from the CLI, a background worker, or the FastAPI app.

### FastAPI backend

The HTTP layer sits at `ioc_enricher/ioc_enricher/web/api/` and is exposed as a
ready-to-run ASGI app. It supports two independent auth modes — server-to-
server **API keys** and browser **user JWT auth** (see the auth sections
below) — and an optional Redis backend for rate limiting and token
revocation.

```bash
# Run the API locally without credentials (single worker; development only —
# debug mode plus the explicit bypass, see "API Security" below):
IOC_WEB_DEBUG=true IOC_WEB_DEV_ALLOW_UNAUTHENTICATED=true uvicorn ioc_enricher.web.api.app:app --reload

# Health check:
curl http://127.0.0.1:8000/api/v1/health

# Single IOC enrichment (Windows cmd line continuation "^"):
curl -X POST http://127.0.0.1:8000/api/v1/enrich ^
     -H "Content-Type: application/json" ^
     -d "{\"ioc\":\"203.0.113.7\",\"ioc_type\":\"ipv4\"}"

# Batch enrichment (max 50 IOCs):
curl -X POST http://127.0.0.1:8000/api/v1/enrich/batch ^
     -H "Content-Type: application/json" ^
     -d "{\"iocs\":[\"203.0.113.7\",\"malicious.example.com\"]}"
```

OpenAPI docs (`/docs`, `/redoc`, `/openapi.json`) are served at
`http://127.0.0.1:8000/docs` in debug mode. A production-like deployment
(`IOC_WEB_DEBUG=false`) does not serve them unless `IOC_WEB_ENABLE_DOCS=true`
(logged as `docs-exposed` at startup).

**Endpoints (all under `/api/v1`)**:

| Method | Path                           | Notes                                        |
|--------|--------------------------------|----------------------------------------------|
| GET    | `/health`                      | Liveness; no secrets in the response.        |
| POST   | `/enrich`                      | Single IOC enrichment.                       |
| POST   | `/enrich/batch`                | Up to 50 IOCs; partial failures supported.   |
| GET    | `/providers`                   | Provider status without API keys.            |
| GET    | `/cache`                       | Cache stats (counts only, no IOC values).    |
| DELETE | `/cache?confirm=true`          | Clear cache. Admin-only (admin key or role). |
| GET    | `/reports/{report_id}`         | UUID-keyed report retrieval.                 |
| POST/GET | `/auth/login`, `/auth/refresh`, `/auth/logout`, `/auth/me` | Browser user auth — see "Browser user authentication (JWT)". |

**Security defaults**:

- With no auth mode configured the API fails closed: protected endpoints
  answer 503 and `DELETE /cache` 403; `/health` stays public.
- All API keys stay in the backend env; nothing secret is ever returned.
- CORS allow-list defaults to local dev origins; `*` is rejected.
- Hardening headers (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`,
  `Permissions-Policy`, `Content-Security-Policy`) are set on every response.
- `X-Request-ID` is generated per request and surfaced in every error payload
  (RFC 7807-style problem JSON).
- Per-IP rate limit on `/enrich` (30/min), `/enrich/batch` (5/min),
  `DELETE /cache` (1/min), `/auth/login` (10/min) and `/auth/refresh`
  (30/min). In-memory by default; **Redis-backed when `IOC_WEB_REDIS_URL` is
  set** — required for correct limiting across multiple workers.
- Structured JSON access logging — never logs request bodies, credential or
  cookie headers, API keys, tokens, or raw client IPs. The client IP is
  logged as a keyed HMAC pseudonym: with `IOC_WEB_ACCESS_LOG_IP_KEY` set it
  is stable across restarts and workers, otherwise the key is random per
  process (correlation within one process only). Pseudonymous, not
  anonymous: whoever holds the key can test candidate addresses. uvicorn's
  own access line is rewritten the same way (client pseudonym, report ids
  cut to 8 hex digits, secret-shaped query values masked), and `urllib3` /
  `requests` records — a retry warning names the provider request path,
  i.e. the IOC and Shodan's `key=` — get the application masking with
  request paths replaced by `/<redacted>`.
- Request bodies are capped at 256 KiB (`IOC_WEB_MAX_BODY_BYTES`).
- A batch stops starting new IOCs after `IOC_WEB_BATCH_DEADLINE_SECONDS`
  (default 120); the rest are reported as `deadline_exceeded`.

**Configuration env vars** (all optional):
`IOC_WEB_DEBUG`, `IOC_WEB_API_PREFIX`, `IOC_WEB_ENABLE_DOCS`,
`IOC_WEB_CORS_ALLOWED_ORIGINS`, `IOC_WEB_RATE_LIMIT_ENABLED`,
`IOC_WEB_RATE_LIMIT_PER_MIN`, `IOC_WEB_BATCH_RATE_LIMIT_PER_MIN`,
`IOC_WEB_CLEAR_CACHE_PER_MIN`, `IOC_WEB_LOGIN_RATE_LIMIT_PER_MIN`,
`IOC_WEB_REFRESH_RATE_LIMIT_PER_MIN`, `IOC_WEB_MAX_BODY_BYTES`,
`IOC_WEB_BATCH_DEADLINE_SECONDS`, `IOC_WEB_TRUST_PROXY_HEADERS`,
`IOC_WEB_TRUSTED_PROXIES`.

**Response shape** (`POST /enrich`; the DTOs in `web/schemas.py` reject
unknown fields):

| Field | Content |
|-------|---------|
| `ioc`, `ioc_type` | Normalised IOC and its type |
| `risk` | `score`, `level`, `reasons`, `detection_confidence`, `breakdown`, `evidence_status` (`complete` / `partial` / `insufficient_data`), `provider_coverage` (`queried`, `responded`, `failed`, `not_found`), `unavailable_providers`, applied floors and URL signals |
| `providers[]` | `name`, `status` (`success`, `not_found`, `rate_limited`, `timeout`, `error`, `unsupported`), `data_summary`, `error`, `response_time_ms` |
| `mitre[]` | `tactic`, `technique_id`, `technique_name`, `description`, `basis`, `evidence` |
| `ai_analysis` | `null` when the AI layer is off; otherwise the narrative, `audit_trail` and `source`: `"ai"` (validated model reply) or `"deterministic"` (rule-based summary) |
| `meta` | `from_cache`, `execution_time_ms`, `timestamp` |
| `report_id` | UUID when `save_report_format` was requested |

`data_summary` holds only allow-listed fields per provider (`web/mappers.py`),
for example Shodan `org`, `vulns_count`, `resolved_ip`; ZeroBounce
`status`, `sub_status`, `domain_age_days`, `mx_found`; VirusTotal `no_result_engines`; AbuseIPDB
`categories`. Report comments and service banners are never included. A real
zero stays `0`, a value the provider returned as unknown stays `null`, a field
the provider did not return is absent, and a failed provider has `{}`; the UI
shows `null` and absent values as "—" (`tests/adapter/test_api_contract.py`).

Error texts (`providers[].error`, problem JSON `detail`, batch `message`) are
sanitised: values after secret names (`api_key=…`), Bearer/Basic credentials,
JWTs and key shapes such as `gsk_…`, `sk-…`, `gh*_…` and `AKIA…` become
`***REDACTED***`.

`POST /enrich/batch` returns `results[]` (same shape as above), `errors[]`
(`ioc`, `error_type` — `validation_error`, `execution_error`,
`deadline_exceeded`, `unknown_error` — and `message`) and a `summary`
(`total`, `unique`, `success`, `failed`, `duplicates_removed`,
`deadline_exceeded`).

### API Security — API Key auth (Phase 2.5)

Both auth modes are off by default, and then the API is **closed**: protected
endpoints answer 503 and admin endpoints 403 (startup logs
`auth-not-configured`). Turn a mode on with environment variables — no `.env`
file is created or required. For local development only, `IOC_WEB_DEBUG=true`
plus `IOC_WEB_DEV_ALLOW_UNAUTHENTICATED=true` serves the non-admin endpoints
without a key; admin endpoints stay closed, and the app refuses to start if
the bypass is set without debug mode.

> ⚠️ **What this is.** The API-key system below is a minimum-viable server-to-
> server / local-demo gate. It is **not** a user-facing authentication system.
> A public React frontend deployed in production must **never** ship the key
> inside its bundle; use a real JWT / session / OAuth flow there. See
> "Production notes" below.

**Enable auth (PowerShell, Windows):**

```powershell
$env:IOC_WEB_AUTH_ENABLED       = "true"
$env:IOC_WEB_API_KEYS           = python -c "import secrets; print(secrets.token_urlsafe(32))"
$env:IOC_WEB_ADMIN_API_KEYS     = python -c "import secrets; print(secrets.token_urlsafe(32))"
uvicorn ioc_enricher.web.api.app:app --reload
```

**Enable auth (Linux / macOS):**

```bash
export IOC_WEB_AUTH_ENABLED=true
export IOC_WEB_API_KEYS="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export IOC_WEB_ADMIN_API_KEYS="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
uvicorn ioc_enricher.web.api.app:app --reload
```

Configured keys are held to the same bar as the JWT secret. Documented
placeholders (values containing words such as `change`, `example`,
`secret`, `replace`) are ignored in every mode; weak keys (shorter than 32
characters, repetitive or sequential) are ignored in debug mode and in
production unless `IOC_WEB_REQUIRE_STRONG_API_KEYS_IN_PROD=false`. A request
with an ignored key gets 403 like any unknown key (an admin route whose keys
are all ignored answers 403 "not configured"), and startup logs
`api-key-rejected` with counts and reasons, never the keys. Always generate
keys as above.

**Call a protected endpoint:**

```bash
curl -H "X-API-Key: $IOC_WEB_API_KEYS" \
     http://127.0.0.1:8000/api/v1/providers
```

**Admin cache clear (requires the *admin* header):**

```bash
curl -X DELETE "http://127.0.0.1:8000/api/v1/cache?confirm=true" \
     -H "X-Admin-API-Key: $IOC_WEB_ADMIN_API_KEYS"
```

**Auth env vars:**

| Variable                              | Default          | Purpose                                              |
|---------------------------------------|------------------|------------------------------------------------------|
| `IOC_WEB_AUTH_ENABLED`                | `false`          | Turn the gate on/off.                                |
| `IOC_WEB_API_KEYS`                    | (empty)          | Comma-separated list of API keys.                    |
| `IOC_WEB_ADMIN_API_KEYS`              | (empty)          | Comma-separated list of admin keys.                  |
| `IOC_WEB_REQUIRE_STRONG_API_KEYS_IN_PROD` | `true`       | `false` accepts weak keys outside debug mode; placeholders stay refused. |
| `IOC_WEB_API_KEY_HEADER_NAME`         | `X-API-Key`      | Header for the standard API key.                     |
| `IOC_WEB_ADMIN_API_KEY_HEADER_NAME`   | `X-Admin-API-Key`| Header for the admin API key.                        |
| `IOC_WEB_ALLOW_HEALTH_WITHOUT_AUTH`   | `true`           | When `false`, `/health` also requires a key.         |
| `IOC_WEB_ALLOW_DOCS_WITHOUT_AUTH`     | `true`           | When `false`, the docs are never served (authenticated docs are not supported). |
| `IOC_WEB_DEV_ALLOW_UNAUTHENTICATED`   | `false`          | Local development only (needs `IOC_WEB_DEBUG=true`): non-admin endpoints without a key. |
| `IOC_WEB_HSTS_ENABLED`                | `false`          | Set to `true` only behind HTTPS.                     |
| `IOC_WEB_HSTS_MAX_AGE`                | `31536000`       | HSTS `max-age` in seconds.                           |

**Endpoint scopes (`auth_enabled=true`):**

| Endpoint                       | Scope               | Header needed              |
|--------------------------------|---------------------|----------------------------|
| `GET /api/v1/health`           | public (default)    | none                       |
| `POST /api/v1/enrich`          | api_key             | `X-API-Key`                |
| `POST /api/v1/enrich/batch`    | api_key             | `X-API-Key`                |
| `GET /api/v1/providers`        | api_key             | `X-API-Key`                |
| `GET /api/v1/cache`            | api_key             | `X-API-Key`                |
| `DELETE /api/v1/cache`         | admin (+`confirm=true`) | `X-Admin-API-Key`     |
| `GET /api/v1/reports/{id}`     | api_key             | `X-API-Key`                |

**Production notes:**

- Treat API keys as secrets — never commit them, never put them in a frontend
  bundle, and rotate them on incident.
- Public React deploys must use a **real** auth system (JWT, session, OAuth);
  the API-key gate is acceptable for server-to-server callers only.
- Run behind HTTPS and set `IOC_WEB_HSTS_ENABLED=true`.
- Replace the in-memory rate limiter with a Redis-backed one before scaling
  beyond a single worker.
- `/docs` is off in production by default; set `IOC_WEB_ENABLE_DOCS=true` only
  if the OpenAPI schema is intentionally public (startup logs `docs-exposed`).
- Keep `DELETE /cache` admin-scoped; never relax it back to a normal API key.

### Browser user authentication (JWT)

For the browser frontend the API key is **not** the answer — a key shipped in
a JS bundle is public. Instead the backend provides a proper user-auth flow:

- **Short-lived JWT access token** — returned in the login response body and
  held only in browser **memory** (never `localStorage`/`sessionStorage`).
- **httpOnly refresh cookie** — long-lived, scoped to `/api/v1/auth`, not
  readable by JS. Used to transparently mint new access tokens.
- **CSRF protection** — a readable CSRF cookie is echoed back in an
  `X-CSRF-Token` header on `refresh`/`logout` (double-submit pattern).
- **Roles** — `admin` and `analyst`; admin endpoints require the admin role.
- The existing API-key auth is **unchanged** and still works for
  server-to-server callers.

**Generate an admin password hash** (the plaintext is never stored or logged):

```bash
python -m ioc_enricher.web.api.security.password   # prompts; nothing is echoed
# -> prints the Argon2 hash (a password passed as an argument would stay in
#    the shell history)
```

**Enable user auth (Linux / macOS):**

```bash
export IOC_WEB_USER_AUTH_ENABLED=true
export IOC_WEB_JWT_SECRET_KEY=$(python -c "import secrets;print(secrets.token_hex(32))")
export IOC_WEB_BOOTSTRAP_ADMIN_USERNAME=admin
export IOC_WEB_BOOTSTRAP_ADMIN_PASSWORD_HASH='<paste the argon2 hash>'
uvicorn ioc_enricher.web.api.app:app --reload
```

**Auth endpoints (under `/api/v1/auth`):**

| Method | Path        | Notes                                                  |
|--------|-------------|--------------------------------------------------------|
| POST   | `/login`    | username/password -> access token + refresh/CSRF cookies |
| POST   | `/refresh`  | refresh cookie + `X-CSRF-Token` -> new access token    |
| POST   | `/logout`   | clears cookies; revokes the refresh token (Redis)      |
| GET    | `/me`       | current user (Bearer access token)                     |

When `IOC_WEB_USER_AUTH_ENABLED` is false the `/auth/*` routes return a safe
404; with a missing or refused JWT secret they return a safe 503.
Documented placeholders and well-known weak values are refused in every
mode, debug included. Otherwise weak secrets (shorter than 32 characters,
repetitive or sequential) are refused in debug mode and in production unless
`IOC_WEB_REQUIRE_STRONG_JWT_SECRET_IN_PROD=false` — keep it `true`.

Tokens are bound to the account they were issued for (an HMAC fingerprint
of the username and password hash, keyed with the JWT secret). Once the
backend runs with a new `IOC_WEB_BOOTSTRAP_ADMIN_PASSWORD_HASH` or username,
every access and refresh token issued before is refused (401) and users
sign in again; a role change applies to the next request. Tokens from a
version without this binding are refused as well, so every user signs in
once after upgrading.

**User-auth env vars:**

| Variable                               | Default            | Purpose                                  |
|----------------------------------------|--------------------|------------------------------------------|
| `IOC_WEB_USER_AUTH_ENABLED`            | `false`            | Turn browser JWT auth on.                |
| `IOC_WEB_JWT_SECRET_KEY`               | (none)             | HMAC signing secret — required, strong.  |
| `IOC_WEB_ACCESS_TOKEN_TTL_MINUTES`     | `15`               | Access token lifetime.                   |
| `IOC_WEB_REFRESH_TOKEN_TTL_DAYS`       | `7`                | Refresh token lifetime.                  |
| `IOC_WEB_REFRESH_COOKIE_SECURE`        | `false`            | `true` behind HTTPS.                     |
| `IOC_WEB_BOOTSTRAP_ADMIN_USERNAME`     | (none)             | Bootstrap login username.                |
| `IOC_WEB_BOOTSTRAP_ADMIN_PASSWORD_HASH`| (none)             | argon2 hash of the bootstrap password.   |
| `IOC_WEB_REDIS_URL`                    | (none)             | Enables Redis rate limit + token revoke. |

### Docker deployment

A three-service stack (Redis + FastAPI backend + nginx frontend) lives in
[`docker/`](docker/README.md):

```bash
# Create docker/.env and the root .env (see docker/README.md), then:
docker compose --env-file docker/.env -f docker/docker-compose.yml config --quiet  # validate
docker compose --env-file docker/.env -f docker/docker-compose.yml up -d --build   # run
# Frontend: http://localhost:3000   (API proxied at /api)
```

Images are multi-stage, run as a **non-root** user, and never bake in
secrets — those are injected at runtime. See [`docker/README.md`](docker/README.md)
for the full production-hardening checklist.

The backend keeps the cache, web reports and its log on the named volumes
`ioc-data`, `ioc-reports` and `ioc-logs`, so they survive `up --build`;
`docker compose down -v` deletes them.

### Continuous integration

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on every push/PR:
backend tests, frontend unit tests + build, Playwright E2E (mocked API),
Playwright E2E against the real FastAPI app with a fake enricher, Docker image
builds with a `docker compose config` check, and a security job: frontend
secret/XSS-sink grep, a **blocking** `pip-audit --strict` over the hashed
locks, a **blocking** `npm audit --audit-level=low`, report-only CycloneDX
SBOMs, a pattern-based secret scan of tracked configuration files and
Bandit (fails on findings of at least medium severity and medium confidence). CI uses no repository secrets and makes no provider or AI calls.
Whether a given commit passed CI is not recorded in this repository.

### Running the tests

The recommended setup installs the hash-pinned test lock and the package
(editable), after which the suites import `ioc_enricher` through the normal
mechanism:

```bash
python -m pip install -r requirements.txt   # = requirements/test.txt (runtime + redis + test)
python -m pip install --no-deps -e .
python -m pytest tests ioc_enricher/tests -q                         # everything
python -m pytest ioc_enricher/tests -q                               # core engine
python -m pytest tests/adapter tests/cli tests/api tests/security -q # web/adapter

# What CI runs (coverage gate 80 %):
python -m pytest ioc_enricher/tests tests/adapter tests/cli tests/api tests/security \
  --cov=ioc_enricher --cov-report=term-missing --cov-fail-under=80 -q
```

> Both test trees can be collected in one invocation (`pyproject.toml` sets
> `--import-mode=importlib`).
>
> `tests/conftest.py` keeps a tiny `sys.path` fallback for a *fresh* checkout
> (before the editable install). It applies to `pytest` and `python -m
> pytest` alike whenever the run includes the `tests/` tree — every command
> above except the core-engine one: the outer `ioc_enricher/` directory that
> `python -m pytest` finds through the current directory is recognised as a
> namespace package, not the package. Without the install, run
> `ioc_enricher/tests` alone with plain `pytest` or set
> `PYTHONPATH=ioc_enricher`.
>
> The suites never read a `.env` (`IOC_ENRICHER_DOTENV=0`) and keep the app
> log on the console (`LOG_FILE` empty), so a test run appends nothing to
> `logs/`.

> **Runtime artifacts.** `logs/`, `reports/` and `data/` (with their
> `ioc_enricher/` counterparts) are runtime directories and are ignored
> entirely by `.gitignore`, `.gitkeep` files included. If a previous commit
> tracked any of them, untrack with e.g.
> `git rm -r --cached logs reports data`.

### Web frontend (Phases 3 & 4)

A React + Vite + TypeScript SOC-style dashboard lives in
[`frontend/`](frontend/) — see [`frontend/README.md`](frontend/README.md) for
full details.

**Phase 4 features:**

- **Batch analysis** (`/analyze/batch`) — paste up to 50 IOCs, with live
  duplicate detection and a sortable/filterable results table.
- **Risk visualization** — SVG risk gauge, level badge, confidence bar and a
  per-provider score breakdown (graceful fallback when not available).
- **MITRE ATT&CK view** — techniques grouped by tactic with safe external
  links to attack.mitre.org.
- **Report export** — copy or download a report (JSON / Markdown / TXT) via a
  client-side Blob; markdown is never converted to HTML.
- **AI analysis panel** — human-review banner, priority-badged
  recommendations, weak-signals section and a collapsible AI audit trail.

**Run the backend (no login, local development only):**

```bash
# PowerShell
$env:IOC_WEB_AUTH_ENABLED = "false"
$env:IOC_WEB_DEBUG = "true"
$env:IOC_WEB_DEV_ALLOW_UNAUTHENTICATED = "true"
uvicorn ioc_enricher.web.api.app:app --reload

# Linux / macOS
IOC_WEB_AUTH_ENABLED=false IOC_WEB_DEBUG=true IOC_WEB_DEV_ALLOW_UNAUTHENTICATED=true \
  uvicorn ioc_enricher.web.api.app:app --reload
```

**Run the frontend:**

```bash
cd frontend
npm ci                       # exact versions from package-lock.json (Node 24)
cp .env.example .env.local   # VITE_API_BASE_URL=http://127.0.0.1:8000
npm run dev                  # http://127.0.0.1:5173
```

The frontend has Dashboard, Analyze, Batch, Providers, Cache and Report pages.
It calls `GET /health`, `POST /enrich`, `POST /enrich/batch`, `GET /providers`,
`GET /cache`, `GET /reports/{id}` and, in `jwt` mode, the `/auth/*`
endpoints. The admin `DELETE /cache` action is intentionally **not** exposed
in the UI.

> ⚠️ **Frontend security.** No API key is ever placed in the frontend bundle —
> anything `VITE_`-prefixed is public. The browser authenticates with the
> **JWT user-auth flow** (`VITE_AUTH_MODE=jwt`): the access token lives in
> memory only, the refresh token is an httpOnly cookie, and CSRF is enforced.
> For a quick local demo without login, run the backend with
> `IOC_WEB_USER_AUTH_ENABLED=false` and `IOC_WEB_AUTH_ENABLED=false` plus the
> development bypass (`IOC_WEB_DEBUG=true`,
> `IOC_WEB_DEV_ALLOW_UNAUTHENTICATED=true`), and the frontend with
> `VITE_AUTH_MODE=disabled`. Provider, AI and report data is
> always rendered as escaped plain text; markdown is never converted to HTML
> and `dangerouslySetInnerHTML` is not used anywhere.

---

## 🎯 Problem Statement & Solution

### ❌ Traditional Method
When a SOC analyst encounters a suspicious IP address, they check several threat-intelligence platforms by hand and combine the answers themselves.

### ✅ With This Tool
A single command (or API call) queries the configured providers concurrently, scores the evidence deterministically and produces one report that also says which providers did not answer.

The repository contains no time-per-IOC measurements. The provider phase of
one IOC is bounded by `IOC_DEADLINE_SECONDS` (default 60 s); actual times
depend on the providers' response times and rate limits (VirusTotal's public
API, for example, allows 4 requests per minute).

---

## 📊 Project Statistics

| Category | Details |
|----------|---------|
| 🔌 Integrations | 6 threat-intelligence providers + 1 optional AI provider (Groq) |
| 🧪 Backend tests | 1,534 collected (`pytest --collect-only`, 2026-10-28) |
| 🧪 Frontend tests | Vitest unit tests and Playwright E2E (mocked and integration) |
| 📏 Coverage gate | 80 % (`--cov-fail-under=80` in CI) |

---

## ✨ Features

### 🔎 Multi-Source Intelligence

| Provider | Capability |
|----------|------------|
| **VirusTotal** | IP, domain, URL and file-hash detections |
| **AbuseIPDB** | IP abuse reports and confidence, Tor flag |
| **Shodan** | Open ports, services and CVE ids for IPs and domains |
| **AlienVault OTX** | Threat pulses for IPs, domains, URLs and hashes |
| **GreyNoise** | Internet-noise / malicious classification of IPs |
| **ZeroBounce** | E-mail validation: toxic, spam-trap, abuse and disposable verdicts, domain age |

### 🤖 AI Narrative (optional)

- **Groq**-powered threat-analysis narrative (the only supported AI backend)
- The AI layer is **strictly additive** — it produces a narrative on top of
  the deterministic score and **never alters the risk score**
- Automated risk scoring (0-100) — deterministic, AI-independent
- Severity classification (LOW/MEDIUM/HIGH/CRITICAL) plus an evidence status
  (`complete` / `partial` / `insufficient_data`)
- Narratives in Turkish (technical terms kept in English), also in the
  deterministic fallback
- Prioritised recommendations; every reply is schema-validated and rejected
  as a whole on any mismatch

### 📊 Multi-Format Reporting

- Colourful terminal output and a plain-text table
- JSON and NDJSON
- Markdown reports
- Web dashboard (React frontend, see above)

### ⚡ Performance and resilience

- Concurrent provider calls (bounded worker pool, `MAX_CONCURRENT_REQUESTS`)
- Batch processing (IOCs one after another)
- Per-provider rate limits with bounded waits, retries, circuit breaker and a
  per-IOC deadline — a failing provider is reported, not fatal
- File cache with TTL and size cap

### 🔎 Supported IOC Types

- IPv4 & IPv6 addresses
- Domain names
- URLs
- File hashes (MD5, SHA1, SHA256)
- Email addresses

---

## 🚀 Installation

### Prerequisites

- Python 3.11 or higher (CI and the backend image use 3.12)
- pip package manager
- Node.js 24 for the frontend (CI uses Node 24)
- Provider API keys — optional; without any key every result is
  `insufficient_data`

### Quick Start

```bash
# Clone the repository
git clone https://github.com/cyb3rkan/ioc-enricher-agent.git
cd ioc-enricher-agent

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install the hash-pinned dependencies and the package
python -m pip install -r requirements.txt
python -m pip install --no-deps -e .

# Setup environment variables
cp .env.example .env
# Edit .env file and add your API keys
```

---

## 🔑 API Keys

This tool uses API keys from the following services:

| Service | Variable | Used for | Registration Link |
|---------|----------|----------|-------------------|
| VirusTotal | `VIRUSTOTAL_API_KEY` | IP, domain, URL, hash | [Get Key](https://www.virustotal.com/gui/join-us) |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | IP | [Get Key](https://www.abuseipdb.com/register) |
| Shodan | `SHODAN_API_KEY` | IP, domain | [Get Key](https://account.shodan.io/register) |
| AlienVault OTX | `OTX_API_KEY` | IP, domain, URL, hash | [Get Key](https://otx.alienvault.com/api) |
| GreyNoise | `GREYNOISE_API_KEY` | IP | [Get Key](https://www.greynoise.io/) |
| ZeroBounce | `ZEROBOUNCE_API_KEY` | E-mail | [Get Key](https://www.zerobounce.net/docs/email-validation-api-quickstart/v2-getting-started) |
| Groq | `GROQ_API_KEY` | Optional AI narrative | [Get Key](https://console.groq.com/keys) |

Every key is optional: a provider without a key is simply not queried. Free
tiers, quotas and terms are set by each provider and are not modelled here —
check them on the provider's site; the client-side pacing defaults are in
[Rate Limiter](docs/en/features/rate-limiter.md).

The AI layer is optional and **Groq-only**. Set `GROQ_API_KEY` to enable it,
or `AI_PROVIDER=disabled` to run with the deterministic scorer only. There is
no OpenAI integration.

### Configuration

Copy `.env.example` to `.env` and add your API keys. **Never commit `.env`.**

```bash
# Threat Intelligence Providers (leave empty to disable a provider)
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
SHODAN_API_KEY=
OTX_API_KEY=
GREYNOISE_API_KEY=
ZEROBOUNCE_API_KEY=

# AI layer — Groq only (groq | disabled); sends IOC data to Groq when a key is set
AI_PROVIDER=groq
GROQ_API_KEY=
GROQ_BASE_URL=https://api.groq.com/openai/v1
GROQ_MODEL=openai/gpt-oss-20b
GROQ_MAX_TOKENS=1200
GROQ_TEMPERATURE=0.2
GROQ_TIMEOUT_SECONDS=30
```

If `AI_PROVIDER` is omitted, Groq auto-enables whenever `GROQ_API_KEY` is set.
An `OPENAI_API_KEY` in the environment is ignored — it never enables the AI
layer.

**Security:** the Groq API key is read server-side from the environment (or
the root `.env`). It is never exposed to the React frontend, the code never
logs it, and the API never returns it — `/health` reports only `status`,
`version`, `providers_configured` and `ai_enabled` (never the key, model name
or base URL). What the AI layer sends to Groq is listed in
[AI Analysis](docs/en/features/ai-analysis.md).

### 🤖 Enabling the Groq AI layer

The AI layer turns deterministic enrichment into a SOC-analyst narrative. It is
powered exclusively by [Groq](https://groq.com), which exposes an
OpenAI-compatible chat-completions HTTP API.

1. **Get a Groq API key** — sign in at
   [console.groq.com/keys](https://console.groq.com/keys) and create a key.
2. **Put the key in the root `.env` only.** Add it to the `.env` file in the
   repository root (the one Docker Compose and the CLI both read):

   ```bash
   AI_PROVIDER=groq
   GROQ_API_KEY=gsk_your_real_key
   ```

3. **Do NOT put the key in the frontend.** The React app never receives any AI
   secret — no `VITE_GROQ_API_KEY`, no build arg, nothing. The browser only
   ever sees the rendered `ai_analysis` narrative the backend returns.
4. **Rebuild / recreate the backend** so the container picks up the new key:

   ```bash
   docker compose -f docker/docker-compose.yml up -d --build backend
   ```

5. **Verify health** (Windows PowerShell — use `curl.exe`, not the `curl`
   alias):

   ```bash
   curl.exe http://127.0.0.1:3000/api/v1/health
   ```

6. **Expected result** — the response includes:

   ```json
   { "ai_enabled": true }
   ```

   `ai_enabled` is `true` only when Groq is genuinely configured. With
   `AI_PROVIDER=disabled` or a missing `GROQ_API_KEY` it reports `false`, and
   the backend keeps running normally — the AI layer simply degrades to the
   deterministic-only result.

#### Docker

In the Docker stack the backend reads the same root `.env` via
`env_file: ../.env` in `docker/docker-compose.yml`. After changing the Groq or
a provider key, recreate just the backend:

```bash
docker compose -f docker/docker-compose.yml up -d --build backend
```

---

## 💻 Usage

### CLI Usage

```bash
# Check provider status
python -m ioc_enricher --status

# Analyze a single IP
python -m ioc_enricher --ip 203.0.113.7

# Analyze a domain
python -m ioc_enricher --domain malicious.example.com

# Analyze a hash (EICAR test file MD5)
python -m ioc_enricher --hash 44d88612fea8a8f36de82e1278abb02f

# Auto-detect IOC type
python -m ioc_enricher --ioc 198.51.100.23

# Batch analysis from file
python -m ioc_enricher --file example_iocs.txt

# Save as JSON
python -m ioc_enricher --ioc 203.0.113.7 --save json

# Generate Markdown report
python -m ioc_enricher --ioc 203.0.113.7 --save markdown
```

Reports go to `ioc_enricher/reports/` as `ioc_<type>_<UTC time>_<random>.<ext>`
(never overwritten, not pruned automatically). All flags, formats and exit
codes: [CLI Usage](docs/en/cli/usage.md).

> The historic `python main.py` invocation now lives at `legacy/main.py` and
> is no longer supported.

### Python API

```python
from ioc_enricher import IOCEnricher

enricher = IOCEnricher()

# Analyze any IOC (type is auto-detected)
result = enricher.enrich("203.0.113.7")
print(result.risk_score.score)            # numeric score 0-100
print(result.risk_score.level.value)      # LOW / MEDIUM / HIGH / CRITICAL
print(result.risk_score.evidence_status)  # complete / partial / insufficient_data
if result.ai_analysis:
    print(result.ai_analysis.summary)
    print(result.ai_analysis.recommendations)

# Batch processing — one EnrichmentResult or exception per input
iocs = ["203.0.113.7", "198.51.100.23", "malicious.example.com"]
results = enricher.enrich_batch(iocs)
```

More: [Enrichment Engine](docs/en/features/enrichment-engine.md).

> The legacy `from src.enricher import IOCEnricher` import path is deprecated.
> Use `from ioc_enricher import IOCEnricher`.

---

## 📊 Sample Output

A real run of the CLI without any provider key (output redirected, so no
colour):

```
🔍 Analysing: 203.0.113.7


══════════════════════════════════════════════════════════════════════
   🔍 IOC ENRICHMENT REPORT
══════════════════════════════════════════════════════════════════════

IOC   :  203.0.113.7
Type  :  IPV4
Time  :  2026-10-29 03:32:47 UTC

──────────────────────────────────────────────────────────────────────
🎯  RISK SCORE:  0/100  ❔  LOW
    Detection Confidence: 0%
    Evidence: insufficient data — no provider was queried; this score is not a clean verdict.
──────────────────────────────────────────────────────────────────────

📊 PROVIDER RESULTS
──────────────────────────────────────────────────────────────────────

══════════════════════════════════════════════════════════════════════

⏱️  Completed in 0.00s
```

With configured providers the report adds score reasons, "why malicious /
why benign" lines, per-provider results, MITRE ATT&CK techniques and — when
the AI layer is enabled — the AI summary with its audit line. The
`Evidence:` line and the ❔ mark say that the `LOW` above means "no
evidence" (`evidence_status: insufficient_data` in `--output json`), not
"clean"; with some providers unavailable it reads `partial — …`.

---

## 📁 Project Structure

```
ioc-enricher-agent/
├── ioc_enricher/
│   ├── ioc_enricher/          # the package (core, providers, models, mitre,
│   │                          # reports, utils, web, cli, enricher.py)
│   ├── tests/                 # package unit tests
│   └── README.md              # package README
├── tests/                     # adapter, api, cli, security, integration tests
├── frontend/                  # React + Vite + TypeScript dashboard
├── docker/                    # Dockerfiles, docker-compose.yml, nginx.conf
├── docs/                      # documentation (en/, tr/ and guides)
├── legacy/                    # deprecated prototype (do not use)
├── requirements/              # hash-pinned locks (runtime, test, build, tools)
├── .github/workflows/ci.yml   # CI
├── example_iocs.txt           # sample IOC list (documentation values)
├── requirements.txt           # = requirements/test.txt
├── pyproject.toml
├── .env.example
├── SECURITY.md
├── LICENSE
└── README.md
```

Runtime directories (`data/`, `logs/`, `reports/`, also under `ioc_enricher/`)
are created on demand and ignored by git; they contain investigation data.

---

## 📖 Documentation

| Document | Description |
|----------|-------------|
| [Documentation index](docs/README.md) | English and Turkish reference documentation |
| [Security policy](SECURITY.md) | Reporting, auth model, AI layer, known limits |
| [Quick Start Guide](docs/Quick_Start.md) | Get up and running |
| [Testing Guide](docs/ReadMe_Test.md) | Testing documentation |
| [Network Troubleshooting](docs/Network_Problems.md) | Fix connection issues |
| [Secret management](docs/SECRET_MANAGEMENT.md) | Handling and rotating keys |
| [Main Documentation (TR)](docs/ReadMe_Main.md) | Detailed feature documentation in Turkish |

---

## 🧪 Testing

Backend commands are in [Running the tests](#running-the-tests) above. The
frontend has its own scripts:

```bash
cd frontend
npm ci
npm run test             # Vitest unit tests
npm run build            # type check + production build
npm run e2e:install      # once: Playwright's Chromium
npm run e2e              # Playwright, mocked API
npm run e2e:integration  # Playwright against the real FastAPI app (fake enricher)
```

No test needs a provider or AI key. This README does not record the result of
any particular run.

---

## 🛡️ Security

| Topic | Implementation |
|-------|----------------|
| API key storage | Environment variables or a git-ignored `.env` file; never CLI arguments |
| Data persistence | **Yes** — cache files (TTL 24 h, size cap), web reports (retention 30 days / 200 MB) and CLI reports (no automatic pruning) contain investigation data |
| Logging | **Yes** — `LOG_FILE` (default `logs/ioc_enricher.log`) and stderr; secrets, tokens, e-mails and URL queries are masked by pattern, IOCs logged as keyed fingerprints |
| Third parties | IOCs go to every configured provider and, when enabled, to Groq |
| Timeouts | Per request, per IOC (`IOC_DEADLINE_SECONDS`) and per web batch |
| Rate limiting | Per provider (client side) and per client on the web API |
| Error handling | Provider failures are reported per provider; API errors are sanitised |

Details and limits: [Security considerations](docs/en/security/considerations.md)
and [SECURITY.md](SECURITY.md).

---

## 🎯 Project Roadmap

| Feature | Status |
|---------|--------|
| Basic IOC parsing (IP, Domain, Hash) | ✅ Complete |
| VirusTotal integration | ✅ Complete |
| AbuseIPDB integration | ✅ Complete |
| Shodan integration | ✅ Complete |
| AlienVault OTX integration | ✅ Complete |
| AI-powered analysis (Groq) | ✅ Complete |
| Batch processing | ✅ Complete |
| Multi-format reporting | ✅ Complete |
| GreyNoise integration | ✅ Complete |
| REST API (FastAPI) | ✅ Complete |
| React/Vite web dashboard | ✅ Complete |
| Browser user auth (JWT + refresh cookie + CSRF) | ✅ Complete |
| Server-to-server API-key auth | ✅ Complete |
| Redis-backed rate limiting + token revocation | ✅ Complete |
| Docker / docker-compose deployment | ✅ Complete |
| GitHub Actions CI + Playwright E2E | ✅ Complete |
| OAuth / OIDC login | 🔜 Planned |
| Persistent user store (Postgres) | 🔜 Planned |
| Analysis history / recent results | 🔜 Planned |

---

## 🤝 Contributing

Contributions are welcome! Please open an issue first to discuss what you would like to change.

```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/ioc-enricher-agent.git

# Create feature branch
git checkout -b feature/amazing-feature

# Commit your changes
git commit -m 'feat: add amazing feature'

# Push to branch
git push origin feature/amazing-feature

# Open Pull Request
```

### Contribution Guidelines

| Requirement | Description |
|-------------|-------------|
| Code Style | Follow PEP 8 standards |
| Test Coverage | CI fails below 80 % (`--cov-fail-under=80`); do not lower coverage |
| Documentation | Update relevant docs |
| Commit Messages | Use conventional commits |

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

This tool is **for educational and authorized security testing purposes only**. Unauthorized use on systems you don't own or have permission to test is illegal. Users are responsible for complying with all applicable laws.

**This tool:**
- Is designed for legitimate security research only
- Is not designed for malicious use
- Use is at user's own responsibility

---

## 🙏 Acknowledgments

| Provider | Purpose |
|----------|---------|
| VirusTotal | Comprehensive malware detection |
| AbuseIPDB | IP reputation data |
| Shodan | Infrastructure intelligence |
| AlienVault OTX | Threat pulse data |
| GreyNoise | Internet-noise classification |
| ZeroBounce | E-mail validation |
| Groq | AI analysis capabilities |

---

## 📧 Contact

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/erkansahin23/)
[![GitHub](https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white)](https://github.com/cyb3rkan)

For questions, issues, or suggestions, please open an issue on GitHub.

---

<div align="center">

**Built with ❤️ for the cybersecurity community**

*Making threat intelligence accessible to everyone*

</div>
