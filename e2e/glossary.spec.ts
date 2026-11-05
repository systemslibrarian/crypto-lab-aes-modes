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

test('a quiz explanation renders its data-why attribute as text', async ({ page }) => {
  // `why` is read back off the quiz card's data-why-* attribute and was interpolated
  // into innerHTML; CodeQL reported js/xss-through-dom at src/helpers.ts:335. The
  // attribute is page copy, so nothing a visitor types reaches it — but the quiz is
  // the one of the two sinks whose value is NOT constrained by a lookup, so it is the
  // one that can be given a payload and observed.
  const payload = '<img src=x onerror="document.title=\'xss\'">';
  await page.goto('.');
  const card = page.locator('.quiz-card').first();
  await card.evaluate((el, value) => el.setAttribute('data-why-wrong', value), payload);

  // Answer wrongly: pick the option that is not this card's data-correct value.
  const correct = await card.getAttribute('data-correct');
  const wrong = card.locator(`input[type="radio"]:not([value="${correct}"])`).first();
  await wrong.check();
  await card.locator('.quiz-check, button').first().click();

  const explain = card.locator('.quiz-explain');
  await expect(explain).toBeVisible();
  await expect(explain).toContainText('Not quite.');
  await expect(explain).toContainText('img src=x onerror=');
  await expect(explain.locator('img')).toHaveCount(0);
  await expect(explain.locator('[onerror]')).toHaveCount(0);
  await expect(page).not.toHaveTitle('xss');
});
