# IOC Enricher — Frontend

React + Vite + TypeScript single-page app for the IOC Enricher Agent API.

A SOC-style threat-intelligence dashboard:

- **Batch analysis** — `/analyze/batch`: paste up to 50 IOCs with live
  duplicate detection; results land in a sortable, risk-filterable table with
  a separate failed-items section.
- **Risk visualization** — SVG risk gauge, colour-coded level badge, a
  detection-confidence bar, and a per-provider score breakdown. When the
  backend supplies a numeric `breakdown` map it renders explicit per-provider
  point bars; otherwise it falls back to grouping `active_data_points`.
- **MITRE ATT&CK view** — techniques grouped by tactic, each linking safely
  to attack.mitre.org (`rel="noopener noreferrer"`).
- **Report export** — copy or download reports as JSON / Markdown / TXT via a
  client-side Blob. Markdown is shown verbatim, never converted to HTML.
- **AI analysis panel** — human-review banner, priority-badged
  recommendations, a weak-signals section, and a collapsible audit trail.
- **Authentication** — optional JWT login flow (see below).

## Requirements

- Node.js 24 LTS and npm (CI and the Docker build use Node 24; Node 20 is end
  of life).
- A running backend (see the repo root README).

## Setup

```bash
cd frontend
npm ci                       # exact versions from package-lock.json
cp .env.example .env.local   # then edit if needed
npm run dev                  # http://127.0.0.1:5173
```

Use `npm install` only when you intend to change dependencies — it may
rewrite `package-lock.json`, which CI and the Docker build install from.

## Environment

Three **non-secret** variables (anything `VITE_`-prefixed is inlined into the
public bundle):

| Variable             | Values                  | Purpose                         |
|----------------------|-------------------------|---------------------------------|
| `VITE_API_BASE_URL`  | URL, or empty           | Backend base URL. Empty = use relative `/api` (Docker/nginx same-origin). |
| `VITE_AUTH_MODE`     | `disabled` \| `jwt`     | UI auth mode (see below).       |
| `VITE_PROTOTYPE_MODE` | `true` \| `1` \| empty | Enables the mock multi-user UI prototype under `/demo` (own demo shell and session; no backend calls; independent of `VITE_AUTH_MODE`). Off by default — keep it off for production builds. |

> ⚠️ **Security.** Never put an API key, admin key, or any secret in `.env`,
> `.env.local`, or this file — the browser never holds an API key. The access
> token is kept in memory only (never `localStorage`/`sessionStorage`).

## Auth modes

### `VITE_AUTH_MODE=disabled` (local demo)

No login screen; all routes are open. Run the backend with
`IOC_WEB_USER_AUTH_ENABLED=false` and `IOC_WEB_AUTH_ENABLED=false` plus the
local-development bypass `IOC_WEB_DEBUG=true` and
`IOC_WEB_DEV_ALLOW_UNAUTHENTICATED=true` — without it the API answers 503.

### `VITE_AUTH_MODE=jwt` (login required)

- `/login` is public; every other route is gated by `ProtectedRoute`.
- Login calls `POST /api/v1/auth/login`; the **access token** is stored in
  memory, the **refresh token** arrives as an httpOnly cookie.
- The API client attaches `Authorization: Bearer <token>`, and on a `401` it
  makes a single `POST /auth/refresh` (with the `X-CSRF-Token` header) and
  retries the request once. A failed refresh drops to the login screen.
- "Sign out" in the topbar calls `POST /auth/logout`, clearing the cookies.

Run the backend with `IOC_WEB_USER_AUTH_ENABLED=true` plus a JWT secret and a
bootstrap admin (see the root README).

## Commands

| Command              | Purpose                                        |
|----------------------|------------------------------------------------|
| `npm run dev`        | Start the dev server on `127.0.0.1:5173`.      |
| `npm run build`      | Strict `tsc -b` type-check + production build. |
| `npm run preview`    | Preview the production build.                  |
| `npm run test`       | Run the Vitest unit suite once.                |
| `npm run test:watch` | Run Vitest in watch mode.                      |
| `npm run e2e`        | Run the Playwright E2E suite (mocked API).     |
| `npm run e2e:integration` | Playwright against the real FastAPI app with a fake enricher (needs the Python environment). |
| `npm run e2e:install`| Install the Playwright browser (one-time).     |

## How results are shown

The UI states what the evidence supports; it never turns missing data into a
clean verdict (`tests/result-semantics.test.tsx`):

- **Evidence status** — `insufficient_data` shows "Yetersiz veri —
  değerlendirme yapılamadı" with a note that the low score reflects missing
  evidence, not safety; `partial` lists the providers that did not answer.
  The batch table marks such rows "Yetersiz veri" / "Kısmi".
- **AI source** — the analysis card is titled "AI Analizi" with the badge
  "AI anlatısı" for a validated model reply, or "Deterministik Analiz" with
  "Deterministik özet — AI kullanılmadı" when the AI layer was off, skipped
  or its reply was unusable. Neither changes the score or the evidence.
- **Missing values** — a provider field the provider did not report (`null`
  in the API) is shown as "—", never as `0` or "clean".
- **Invisible characters** — control, bidi and zero-width characters in
  IOCs, provider text and AI output are shown as markers such as `[U+202E]`
  (`src/lib/safeRender.ts`); copied and downloaded values stay raw. Long
  values are cut for display.

## Architecture

```
src/
  auth/       AuthProvider, useAuth, ProtectedRoute, authApi, tokenStore
  lib/        api client, config, formatting, batch/download/safe-render helpers
  types/      TypeScript mirror of the backend DTOs
  hooks/      tiny async-state hooks (useQuery / useMutation)
  components/ layout, common UI, risk, mitre, batch, enrich, providers, cache
  pages/      Dashboard, Analyze, BatchAnalyze, Providers, Cache, Report, Login, NotFound
e2e/          Playwright specs + the shared API mock
```

- **Security:** `dangerouslySetInnerHTML` is not used anywhere (enforced by
  `tests/security-regression.test.ts`, which also asserts no API-key header
  and no token in web storage). All backend strings render as escaped plain
  text; markdown is never converted to HTML. External links use
  `rel="noopener noreferrer"`. Clipboard copy and file download only run on an
  explicit user click.
