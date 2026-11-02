import { expect, test, type Page } from "@playwright/test";

/**
 * Real-backend session lifecycle: login, reload (silent refresh with CSRF),
 * refresh-token rotation + replay rejection, logout revocation, failed
 * refresh. See playwright.integration.config.ts.
 *
 * Credentials are the fixed test-only values from tests/integration/e2e_server.py.
 */
const API = "http://127.0.0.1:8765/api/v1";
const USER = "e2e-admin";
const PASS = "E2E-Integration-Pass-1!";

async function login(page: Page) {
  await page.goto("/login");
  await page.getByLabel(/Kullanıcı Adı/i).fill(USER);
  await page.getByLabel(/Parola/i).fill(PASS);
  await page.getByRole("button", { name: /^Giriş Yap$/ }).click();
  await expect(page.getByRole("button", { name: /Çıkış Yap/ }).first()).toBeVisible();
}

async function cookie(page: Page, name: string) {
  return (await page.context().cookies()).find((c) => c.name === name);
}

test.describe("session lifecycle against the real backend", () => {
  test("login sets an httpOnly refresh cookie and a JS-readable CSRF cookie", async ({ page }) => {
    await login(page);
    const refresh = await cookie(page, "ioc_refresh_token");
    expect(refresh?.httpOnly).toBe(true);
    expect(refresh?.path).toBe("/api/v1/auth");
    const visible = await page.evaluate(() => document.cookie);
    expect(visible).toContain("ioc_csrf_token=");
    expect(visible).not.toContain("ioc_refresh_token");
    // The access token never lands in web storage.
    const storage = await page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage }));
    expect(storage).toBe("{}");
  });

  test("a full page reload keeps the session via silent refresh", async ({ page }) => {
    await login(page);
    await page.goto("/analyze");
    // Immediate reload: may interrupt the silent refresh started by goto().
    // In-flight races are covered in depth by refresh-race.spec.ts.
    await page.reload();
    await expect(page).toHaveURL(/\/analyze$/);
    await expect(page.getByRole("button", { name: /Çıkış Yap/ }).first()).toBeVisible();

    // The renewed access token works for a protected API call.
    await page.getByLabel(/Gösterge \(IOC\)/i).fill("evil.example.com");
    await page.getByRole("button", { name: /^Analiz Et$/ }).click();
    await expect(page.getByText("CRITICAL").first()).toBeVisible();
  });

  test("refresh tokens rotate and a replayed token is rejected", async ({ page, request }) => {
    await login(page);
    const before = await cookie(page, "ioc_refresh_token");
    await page.reload();
    await expect(page.getByRole("button", { name: /Çıkış Yap/ }).first()).toBeVisible();
    const after = await cookie(page, "ioc_refresh_token");
    expect(after?.value).toBeTruthy();
    expect(after?.value).not.toBe(before?.value);

    const csrf = (await cookie(page, "ioc_csrf_token"))!.value;
    const replay = await request.post(`${API}/auth/refresh`, {
      headers: { "X-CSRF-Token": csrf, Cookie: `ioc_refresh_token=${before!.value}; ioc_csrf_token=${csrf}` },
    });
    expect(replay.status()).toBe(401);
  });

  test("refresh without the CSRF header is refused", async ({ page }) => {
    await login(page);
    const res = await page.request.post(`${API}/auth/refresh`);
    expect(res.status()).toBe(403);
  });

  test("logout revokes the session server-side", async ({ page, request }) => {
    await login(page);
    const refresh = (await cookie(page, "ioc_refresh_token"))!.value;
    const csrf = (await cookie(page, "ioc_csrf_token"))!.value;

    await page.getByRole("button", { name: /Çıkış Yap/ }).first().click();
    await expect(page).toHaveURL(/\/login$/);
    await expect.poll(async () => !!(await cookie(page, "ioc_refresh_token"))).toBe(false);

    // Reload stays logged out, and the old refresh token is dead.
    await page.reload();
    await expect(page).toHaveURL(/\/login$/);
    const res = await request.post(`${API}/auth/refresh`, {
      headers: { "X-CSRF-Token": csrf, Cookie: `ioc_refresh_token=${refresh}; ioc_csrf_token=${csrf}` },
    });
    expect(res.status()).toBe(401);
  });

  test("a failed refresh sends the user back to the login page", async ({ page }) => {
    await login(page);
    const current = (await cookie(page, "ioc_refresh_token"))!;
    await page.context().addCookies([{ ...current, value: "tampered.not.a.jwt" }]);

    await page.goto("/providers");
    await expect(page).toHaveURL(/\/login$/);
    await expect(page.getByRole("button", { name: /^Giriş Yap$/ })).toBeVisible();
  });
});
