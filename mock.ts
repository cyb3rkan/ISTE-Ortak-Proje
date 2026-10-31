/**
 * Shared API mocking for the E2E suite.
 *
 * Every `/api/v1/*` request is fulfilled by `page.route()` — no real backend
 * is contacted. This models a logged-in admin and a small set of enrichment
 * responses. The auth endpoints emulate the cookie + CSRF behaviour closely
 * enough to drive the UI flows.
 */
import type { Page, Route } from "@playwright/test";

const ACCESS_TOKEN = "e2e-access-token";

const HEALTH = {
  status: "ok",
  service: "ioc-enricher",
  version: "2.0.0",
  providers_configured: 2,
  ai_enabled: false,
};

const PROVIDERS = {
  providers: [
    {
      name: "VirusTotal",
      enabled: true,
      configured: true,
      status: "ready",
      last_error: null,
    },
    {
      name: "AbuseIPDB",
      enabled: true,
      configured: true,
      status: "ready",
      last_error: null,
    },
  ],
  ai_enabled: false,
};

const ENRICHMENT = {
  ioc: "8.8.8.8",
  ioc_type: "ipv4",
  risk: {
    score: 18,
    level: "LOW",
    reasons: ["No malicious detections"],
    detection_confidence: 0.9,
    active_data_points: ["virustotal.harmless"],
    breakdown: { virustotal: 10, abuseipdb: 8 },
  },
  providers: [
    {
      name: "VirusTotal",
      status: "success",
      data_summary: { malicious: 0, harmless: 70 },
      error: null,
      response_time_ms: 120,
    },
  ],
  mitre: [],
  ai_analysis: null,
  meta: { from_cache: false, execution_time_ms: 12, request_id: "e2e-1" },
  report_id: null,
};

function json(route: Route, body: unknown, status = 200) {
  return route.fulfill({
    status,
    contentType: "application/json",
    body: JSON.stringify(body),
  });
}

/**
 * Install the full API mock on a page. `authed` controls whether the initial
 * silent refresh succeeds (simulating a returning, logged-in user).
 */
export async function installApiMock(
  page: Page,
  opts: { authed?: boolean; enrichment?: unknown } = {},
): Promise<void> {
  let loggedIn = opts.authed ?? false;
  const enrichment = opts.enrichment ?? ENRICHMENT;

  await page.route("**/api/v1/**", async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    const method = route.request().method();

    // --- auth ---
    if (path.endsWith("/auth/login") && method === "POST") {
      const payload = route.request().postDataJSON() as {
        username?: string;
        password?: string;
      };
      if (payload?.username === "admin" && payload?.password === "Adm1nPass") {
        loggedIn = true;
        return route.fulfill({
          status: 200,
          contentType: "application/json",
          headers: {
            "set-cookie":
              "ioc_csrf_token=e2e-csrf; Path=/api/v1/auth; SameSite=Lax",
          },
          body: JSON.stringify({
            access_token: ACCESS_TOKEN,
            token_type: "bearer",
            expires_in: 900,
            user: { username: "admin", role: "admin" },
          }),
        });
      }
      // Mirrors the real backend's generic 401 (web/api/routers/auth.py).
      return json(route, { detail: "Geçersiz kullanıcı adı veya şifre." }, 401);
    }

    if (path.endsWith("/auth/refresh") && method === "POST") {
      if (loggedIn) {
        return json(route, {
          access_token: ACCESS_TOKEN,
          token_type: "bearer",
          expires_in: 900,
          user: { username: "admin", role: "admin" },
        });
      }
      return json(route, { detail: "No refresh token." }, 401);
    }

    if (path.endsWith("/auth/logout") && method === "POST") {
      loggedIn = false;
      return json(route, { logged_out: true });
    }

    if (path.endsWith("/auth/me") && method === "GET") {
      if (loggedIn) {
        return json(route, { username: "admin", role: "admin" });
      }
      return json(route, { detail: "Unauthorized." }, 401);
    }

    // --- data endpoints ---
    if (path.endsWith("/health")) return json(route, HEALTH);
    if (path.endsWith("/providers")) return json(route, PROVIDERS);
    if (path.endsWith("/enrich") && method === "POST") {
      return json(route, enrichment);
    }
    if (path.endsWith("/cache") && method === "GET") {
      return json(route, { entries: 3, size_bytes: 4096, ttl_hours: 24 });
    }

    // Fallback — anything unmocked fails loudly.
    return json(route, { detail: "Not mocked." }, 404);
  });
}
