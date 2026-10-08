import { expect, test } from '@playwright/test';

for (const width of [380, 1280]) {
  test(`focused glossary definitions fit the viewport at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 720 });
    await page.goto('.');
    await expect(page.locator('.glossary-term').first()).toBeVisible();
    const terms = page.locator('.glossary-term:visible');
    for (const term of await terms.all()) {
      await term.focus();
      const tip = term.locator('.glossary-tip');
      await expect(tip).toBeVisible();
      await expect.poll(() => tip.evaluate((el) => {
        const r = el.getBoundingClientRect();
        return r.left >= 0 && r.top >= 0 &&
          r.right <= window.innerWidth && r.bottom <= window.innerHeight &&
          document.documentElement.scrollWidth <= window.innerWidth;
      })).toBe(true);
    }
  });
}
