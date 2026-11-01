import { expect, test } from "@playwright/test";

/**
 * Report workflow against the real backend: analyse an IOC with
 * "Rapor kaydet" selected, follow the link from the result, and read the
 * persisted report (EnrichmentService + ReportStore are real).
 */
const USER = "e2e-admin";
const PASS = "E2E-Integration-Pass-1!";

test.beforeEach(async ({ page }) => {
  await page.goto("/login");
  await page.getByLabel(/Kullanıcı Adı/i).fill(USER);
  await page.getByLabel(/Parola/i).fill(PASS);
  await page.getByRole("button", { name: /^Giriş Yap$/ }).click();
  await expect(page.getByRole("button", { name: /Çıkış Yap/ }).first()).toBeVisible();
});

for (const [label, format] of [["Markdown", "markdown"], ["JSON", "json"]] as const) {
  test(`saving a ${format} report links to the report page`, async ({ page }) => {
    await page.getByRole("link", { name: /^Analiz$/ }).first().click();
    await page.getByLabel(/Gösterge \(IOC\)/i).fill("evil.example.com");
    await page.getByLabel(/Rapor kaydet/i).selectOption({ label });
    await page.getByRole("button", { name: /^Analiz Et$/ }).click();

    const link = page.getByRole("link", { name: /Raporu görüntüle/ });
    await expect(link).toBeVisible();
    await link.click();

    await expect(page).toHaveURL(/\/reports\/[0-9a-f-]{36}$/);
    await expect(page.getByText(`Rapor · ${format}`)).toBeVisible();
    await expect(page.getByText(/evil\.example\.com/).first()).toBeVisible();
  });
}

test("analysing without saving shows no report link", async ({ page }) => {
  await page.getByRole("link", { name: /^Analiz$/ }).first().click();
  await page.getByLabel(/Gösterge \(IOC\)/i).fill("8.8.8.8");
  await page.getByRole("button", { name: /^Analiz Et$/ }).click();
  await expect(page.getByText("LOW").first()).toBeVisible();
  await expect(page.getByRole("link", { name: /Raporu görüntüle/ })).toHaveCount(0);
});
