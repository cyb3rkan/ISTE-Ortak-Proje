import { expect, test, type BrowserContext, type Page } from "@playwright/test";

/**
 * Refresh-token race regressions (real backend).
 *
 * The integration server holds every /auth/refresh response for 600 ms AFTER
 * the old refresh token has been consumed and its successor minted
 * (--refresh-delay-ms). That makes the dangerous window deterministic:
 * a reload / second tab that fires while a rotation is in flight.
 *
 * Refresh tokens stay strictly single-use on the server: these tests also pin
 * down that a consumed token never yields credentials to anyone.
 */
const API = "http://127.0.0.1:8765/api/v1";
const USER = "e2e-admin";
const PASS = "E2E-Integration-Pass-1!";

async function login(page: Page) {
  await page.goto("/login");
  await page.getByLabel(/Kullanıcı Adı/i).fill(USER);
  await page.getByLabel(/Parola/i).fill(PASS);
  await page.getByRole("button", { name: /^Giriş Yap$/ }).click();
  await expect(signedIn(page)).toBeVisible();
}

const signedIn = (page: Page) => page.getByRole("button", { name: /Çıkış Yap/ }).first();

async function cookieValue(context: BrowserContext, name: string) {
  return (await context.cookies()).find((c) => c.name === name)?.value;
}

/** Navigate and return as soon as the app's silent refresh has been SENT. */
async function gotoUntilRefreshSent(page: Page, path: string) {
  const sent = page.waitForRequest(
    (r) => r.url().endsWith("/auth/refresh") && r.method() === "POST",
  );
  await page.goto(path, { waitUntil: "commit" });
  await sent;
}

test.describe("refresh races", () => {
  test("reload while a refresh is in flight keeps the session", async ({ page }) => {
    await login(page);
    await gotoUntilRefreshSent(page, "/analyze");
    await page.reload(); // interrupts the in-flight rotation
    await expect(page).toHaveURL(/\/analyze$/);
    await expect(signedIn(page)).toBeVisible();
  });

  test("several rapid reloads in a row keep the session", async ({ page }) => {
    await login(page);
    for (const path of ["/analyze", "/providers", "/cache"]) {
      await gotoUntilRefreshSent(page, path);
    }
    await page.reload();
    await expect(page).toHaveURL(/\/cache$/);
    await expect(signedIn(page)).toBeVisible();
  });

  test("three tabs loading at the same time all stay signed in", async ({ page, context }) => {
    await login(page);
    const tabs = [page, await context.newPage(), await context.newPage()];
    await Promise.all(tabs.map((t, i) => t.goto(["/analyze", "/providers", "/cache"][i])));
    for (const t of tabs) {
      await expect(signedIn(t)).toBeVisible();
      await expect(t).not.toHaveURL(/\/login$/);
    }
  });

  test("a stolen, already-consumed token never yields credentials", async ({ page, context, request }) => {
    await login(page);
    const stolen = (await cookieValue(context, "ioc_refresh_token"))!;
    const csrf = (await cookieValue(context, "ioc_csrf_token"))!;

    // Legit rotation in flight. "Sent" is not "processed" (CORS preflight,
    // scheduling), so give the server time to commit the rotation; the
    // response is still held for the remainder of the 600 ms window.
    await gotoUntilRefreshSent(page, "/analyze");
    await page.waitForTimeout(300);
    const attack = await request.post(`${API}/auth/refresh`, {
      headers: { "X-CSRF-Token": csrf, Cookie: `ioc_refresh_token=${stolen}; ioc_csrf_token=${csrf}` },
    });
    expect(attack.status()).toBe(401);
    expect(await attack.text()).not.toContain("access_token");
    expect(attack.headers()["set-cookie"] ?? "").not.toContain("ioc_refresh_token=ey");

    // The legitimate user is unaffected.
    await expect(signedIn(page)).toBeVisible();
  });

  test("revocation-store outage (503) fails closed without hanging", async ({ page }) => {
    await login(page);
    // Simulates the server's fail-closed answer when Redis is unreachable
    // (backend behaviour itself is covered by tests/security/test_refresh_rotation.py).
    await page.route("**/api/v1/auth/refresh", (route) =>
      route.fulfill({
        status: 503,
        contentType: "application/problem+json",
        body: JSON.stringify({ detail: "Kimlik doğrulama geçici olarak kullanılamıyor." }),
      }),
    );
    const started = Date.now();
    await page.goto("/providers");
    await expect(page).toHaveURL(/\/login$/);
    expect(Date.now() - started).toBeLessThan(4_000);
    const marker = await page.evaluate(() => localStorage.getItem("ioc-enricher:rotation-in-flight"));
    expect(marker).toBeNull();
  });

  test("RESIDUAL RISK: a thief who uses a token first wins once; the victim is signed out", async ({ page, context, request }) => {
    await login(page);
    const stolen = (await cookieValue(context, "ioc_refresh_token"))!;
    const csrf = (await cookieValue(context, "ioc_csrf_token"))!;
    const headers = { "X-CSRF-Token": csrf, Cookie: `ioc_refresh_token=${stolen}; ioc_csrf_token=${csrf}` };

    // Inherent to bearer refresh tokens: the first presenter gets the successor.
    expect((await request.post(`${API}/auth/refresh`, { headers })).status()).toBe(200);
    // ...but only once.
    expect((await request.post(`${API}/auth/refresh`, { headers })).status()).toBe(401);

    // The victim's next refresh fails (reuse is logged server-side) -> login.
    await page.goto("/providers");
    await expect(page).toHaveURL(/\/login$/);
  });
});
