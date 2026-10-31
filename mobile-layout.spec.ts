import { expect, test, type Locator } from "@playwright/test";

import { installApiMock } from "./mock";

/**
 * Mobile layout: the top bar must not wrap, the bottom navigation must offer
 * comfortable touch targets, and nothing may overflow horizontally.
 */
async function singleLine(locator: Locator) {
  // Count the distinct visual lines the element's *rendered* text occupies.
  const lines = await locator.evaluate((el) => {
    // Text nodes only: decorative boxes (e.g. the status dot) are not lines.
    const tops = new Set<number>();
    const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
      const range = document.createRange();
      range.selectNodeContents(n);
      for (const r of Array.from(range.getClientRects())) {
        if (r.width > 0 && r.height > 0) tops.add(Math.round(r.top));
      }
    }
    return tops.size;
  });
  expect(lines).toBe(1);
}

for (const width of [320, 390]) {
  test.describe(`mobile layout @ ${width}px`, () => {
    test.use({ viewport: { width, height: 800 }, hasTouch: true, isMobile: true });

    test.beforeEach(async ({ page }) => {
      await installApiMock(page, { authed: true });
      await page.goto("/analyze");
      await expect(page.getByRole("button", { name: /Çıkış Yap/ })).toBeVisible();
    });

    test("top bar controls stay on one line", async ({ page }) => {
      const header = page.getByRole("banner");
      await singleLine(header.getByText("IOC Enricher"));
      await singleLine(header.getByRole("status"));
      await singleLine(page.getByRole("button", { name: /Çıkış Yap/ }));
      const box = await header.boundingBox();
      expect(box!.height).toBeLessThanOrEqual(56);
    });

    test("backend status keeps its full description for assistive tech", async ({ page }) => {
      const badge = page.getByRole("banner").getByTitle(/provider yapılandırıldı/);
      await expect(badge).toBeVisible();
      await expect(badge).toHaveAccessibleName(/Backend çevrimiçi · v2\.0\.0/);
    });

    test("bottom navigation has 44px touch targets and marks the current page", async ({ page }) => {
      const nav = page.getByRole("navigation", { name: /mobil/i });
      const links = nav.getByRole("link");
      await expect(links).toHaveCount(5);
      for (const link of await links.all()) {
        const box = await link.boundingBox();
        expect(box!.height).toBeGreaterThanOrEqual(44);
        await singleLine(link);
      }
      await expect(nav.getByRole("link", { name: "Analiz" })).toHaveAttribute("aria-current", "page");
    });

    test("no horizontal overflow", async ({ page }) => {
      const overflow = await page.evaluate(
        () => document.documentElement.scrollWidth - window.innerWidth,
      );
      expect(overflow).toBeLessThanOrEqual(0);
    });
  });
}

test("desktop keeps the sidebar and hides the mobile bar", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await installApiMock(page, { authed: true });
  await page.goto("/");
  await expect(page.getByRole("navigation", { name: "Primary" })).toBeVisible();
  await expect(page.getByRole("navigation", { name: /mobil/i })).toBeHidden();
  await expect(page.getByRole("banner").getByText(/Backend çevrimiçi · v2\.0\.0/)).toBeVisible();
});
