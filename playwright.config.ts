import { defineConfig, devices } from "@playwright/test";

/**
 * Playwright E2E configuration.
 *
 * Strategy: **mocked API**. Every test intercepts the backend with
 * `page.route()` (see e2e/mock.ts) — no real backend, no Redis, no provider
 * network calls. This keeps CI fast and fully deterministic.
 *
 * The app under test is served by `vite preview` from a production build that
 * was made with `VITE_AUTH_MODE=jwt` so the login/auth flow is exercised.
 *
 * Run:  npm run e2e        (expects `npm run build` to have produced ./dist)
 */
const PORT = 4173;

export default defineConfig({
  testDir: "./e2e",
  timeout: 30_000,
  expect: { timeout: 5_000 },
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? "line" : "list",
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    trace: "on-first-retry",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  // Build with jwt auth mode, then serve the static bundle.
  webServer: {
    command: `npm run build && npm run preview -- --port ${PORT} --strictPort`,
    url: `http://127.0.0.1:${PORT}`,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
    env: {
      VITE_AUTH_MODE: "jwt",
      VITE_API_BASE_URL: "",
    },
  },
});
