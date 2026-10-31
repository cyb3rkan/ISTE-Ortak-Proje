import { expect, test } from "@playwright/test";

import { installApiMock } from "./mock";

/**
 * Auth E2E — login, protected-route redirect, logout.
 * Runs against the jwt-mode build with a fully mocked API.
 */

test.describe("authentication", () => {
  test("anonymous visitor is redirected to the login page", async ({
    page,
  }) => {
    await installApiMock(page, { authed: false });
    await page.goto("/");
    // ProtectedRoute -> /login.
    await expect(page).toHaveURL(/\/login$/);
    await expect(
      page.getByRole("button", { name: /^Giriş Yap$/i }),
    ).toBeVisible();
  });

  test("valid login reaches the dashboard", async ({ page }) => {
    await installApiMock(page, { authed: false });
    await page.goto("/login");

    await page.getByLabel(/Kullanıcı Adı/i).fill("admin");
    await page.getByLabel(/Parola/i).fill("Adm1nPass");
    await page.getByRole("button", { name: /^Giriş Yap$/i }).click();

    await expect(page).toHaveURL(/\/$/);
    // The topbar shows the signed-in user + a sign-out control.
    await expect(
      page.getByRole("button", { name: /Çıkış Yap/i }),
    ).toBeVisible();
  });

  test("login returns the user to the originally requested page", async ({
    page,
  }) => {
    await installApiMock(page, { authed: false });
    await page.goto("/providers");
    await expect(page).toHaveURL(/\/login$/);

    await page.getByLabel(/Kullanıcı Adı/i).fill("admin");
    await page.getByLabel(/Parola/i).fill("Adm1nPass");
    await page.getByRole("button", { name: /^Giriş Yap$/i }).click();

    await expect(page).toHaveURL(/\/providers$/);
  });

  test("invalid login shows a generic error", async ({ page }) => {
    await installApiMock(page, { authed: false });
    await page.goto("/login");

    await page.getByLabel(/Kullanıcı Adı/i).fill("admin");
    await page.getByLabel(/Parola/i).fill("wrong-password");
    await page.getByRole("button", { name: /^Giriş Yap$/i }).click();

    await expect(page.getByRole("alert")).toContainText(
      /Geçersiz kullanıcı adı veya şifre/i,
    );
    await expect(page).toHaveURL(/\/login$/);
  });

  test("logout returns the user to the login page", async ({ page }) => {
    await installApiMock(page, { authed: true });
    await page.goto("/");
    await expect(
      page.getByRole("button", { name: /Çıkış Yap/i }),
    ).toBeVisible();

    await page.getByRole("button", { name: /Çıkış Yap/i }).click();
    await expect(page).toHaveURL(/\/login$/);
  });
});
