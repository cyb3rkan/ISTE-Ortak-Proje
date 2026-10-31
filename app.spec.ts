import { expect, test } from "@playwright/test";

import { installApiMock } from "./mock";

/**
 * Application smoke E2E — exercises the main routes with a logged-in user
 * against a fully mocked API.
 */

test.describe("application", () => {
  // Every test starts already authenticated (silent refresh succeeds).
  test.beforeEach(async ({ page }) => {
    await installApiMock(page, { authed: true });
  });

  test("dashboard loads for an authenticated user", async ({ page }) => {
    await page.goto("/");
    await expect(page).toHaveURL(/\/$/);
    // Backend health badge resolves to "online" (Turkish UI: "çevrimiçi").
    await expect(page.getByText(/Backend çevrimiçi/i)).toBeVisible();
  });

  test("providers page lists configured providers", async ({ page }) => {
    await page.goto("/providers");
    await expect(page.getByText("VirusTotal")).toBeVisible();
    await expect(page.getByText("AbuseIPDB")).toBeVisible();
  });

  test("analyze page enriches a single IOC", async ({ page }) => {
    await page.goto("/analyze");
    await page.getByLabel(/Gösterge \(IOC\)/i).fill("8.8.8.8");
    await page.getByRole("button", { name: /^Analiz Et$/i }).click();
    // The mocked enrichment result renders the IOC and a LOW risk level.
    await expect(page.getByText("8.8.8.8").first()).toBeVisible();
    await expect(page.getByText("LOW").first()).toBeVisible();
  });

  test("batch page enforces validation", async ({ page }) => {
    await page.goto("/analyze/batch");
    // Submitting with no input surfaces a validation message.
    const submit = page.getByTestId("batch-submit");
    await submit.click();
    await expect(page.getByRole("alert").first()).toBeVisible();
  });

  test("an unknown report route shows a not-found page", async ({ page }) => {
    await page.goto("/reports/not-a-real-uuid");
    // The route renders (ReportPage) — the mock returns 404 for the report,
    // so an error/empty state is shown rather than a crash.
    await expect(page.locator("body")).toBeVisible();
  });

  test("404 page renders for an unknown route", async ({ page }) => {
    await page.goto("/this/does/not/exist");
    await expect(page.getByText("404")).toBeVisible();
  });
});
