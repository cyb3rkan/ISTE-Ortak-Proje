import { defineConfig, devices } from "@playwright/test";

/**
 * Browser ↔ real-backend integration E2E.
 *
 * Unlike `playwright.config.ts` (fully mocked API), this suite starts the
 * REAL FastAPI app (tests/integration/e2e_server.py — real JWT, httpOnly
 * refresh cookie, CSRF, refresh rotation, rate limiting) with a fake,
 * offline enricher, plus a production build of the SPA pointed at it.
 * No provider / AI API is contacted and no .env is read.
 *
 * Run:  npm run e2e:integration
 *       (E2E_PYTHON selects the interpreter; default "python")
 */
const API_PORT = 8765;
const WEB_PORT = 4175;
const PYTHON = process.env.E2E_PYTHON ?? "python";

export default defineConfig({
  testDir: "./e2e-integration",
  timeout: 60_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? "line" : "list",
  outputDir: "./test-results-integration",
  use: {
    baseURL: `http://127.0.0.1:${WEB_PORT}`,
    trace: "on-first-retry",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: [
    {
      command: `"${PYTHON}" ../tests/integration/e2e_server.py --port ${API_PORT} --frontend-origin http://127.0.0.1:${WEB_PORT} --refresh-delay-ms 600`,
      url: `http://127.0.0.1:${API_PORT}/api/v1/health`,
      reuseExistingServer: false,
      timeout: 60_000,
    },
    {
      command: `npx vite build --outDir dist-integration && npx vite preview --outDir dist-integration --port ${WEB_PORT} --strictPort`,
      url: `http://127.0.0.1:${WEB_PORT}`,
      reuseExistingServer: false,
      timeout: 180_000,
      env: {
        VITE_AUTH_MODE: "jwt",
        VITE_API_BASE_URL: `http://127.0.0.1:${API_PORT}`,
      },
    },
  ],
});
