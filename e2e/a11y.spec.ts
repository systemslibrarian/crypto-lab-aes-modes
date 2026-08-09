import { test } from '@playwright/test';
import { boot, driveAllStates, NARROW } from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven the way a visitor drives it and scanned after every single
 * step: all seven mode tabs opened one at a time, each panel encrypted, every
 * vulnerability demo run, every decrypt variant (correct, wrong key, wrong IV,
 * wrong nonce, wrong AAD, tampered) rendered in its own right, the ECB penguin
 * comparison driven with a real uploaded image, the live GCM forbidden attack
 * run and controlled, the five-mode comparison built with and without repeated
 * blocks, the padding oracle set up and run to full recovery, and every
 * self-check answered both right and wrong. Every resulting state is scanned in
 * both themes at desktop and phone width.
 *
 * See `gate.ts` for why nothing is injected into the page, why no `[hidden]`
 * attribute is stripped and no `<details>` forced open from script, why the
 * drive asserts this lab's defaults instead of assuming them, why every step is
 * scanned rather than only the last, and why `violations` is not the whole
 * oracle.
 */

for (const theme of ['dark', 'light'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(1_800_000);
    await boot(page, theme);
    await driveAllStates(page, theme);
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(1_800_000);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
  });
}
