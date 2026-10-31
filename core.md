# Frontend (frontend/)

React 18 + TypeScript + Vite 6 + Tailwind 4 (CSS-first `@theme` in src/styles/globals.css, `@tailwindcss/postcss`; no tailwind.config.js) + react-router 7 (import from "react-router", not react-router-dom; no `future` props). No state lib, no UI kit. UI text is Turkish — E2E selectors must use the Turkish accessible names. Post-login redirects go through src/auth/safeRedirect.ts.

## Structure (`frontend/src/`)
- `lib/api.ts` — single API client (`getHealth`, `enrichSingle`, `enrichBatch`, `getProviders`, `getCacheStats`, `getReport`, `describeError`); attaches Bearer token, single-shot 401 → refresh → retry.
- `auth/` — `AuthProvider`/`useAuth`, `ProtectedRoute`, `authApi.ts`, `tokenStore.ts`. Access token lives ONLY in module memory (never localStorage/sessionStorage); refresh via httpOnly cookie.
- `hooks/use*.ts` — data hooks over `useAsync`; `pages/*Page.tsx` routed in `routes.tsx`; `components/<feature>/` (enrich, batch, risk, mitre, providers, cache, layout, common).
- `lib/safeRender.ts` — sanitize untrusted provider/AI text; `dangerouslySetInnerHTML` is banned (CI grep).
- `types/api.ts` — TS mirrors of backend `web/schemas.py` DTOs; keep in sync on API changes.
- `lib/config.ts` reads `VITE_*` env; never put provider/API keys there.

## Tests
- Vitest + Testing Library + jsdom: `frontend/tests/*.test.ts(x)`, setup `src/test/setup.ts`.
- Playwright E2E with mocked API: `frontend/e2e/*.spec.ts` (`e2e/mock.ts`), chromium only.
