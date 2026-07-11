import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Deploys are already gated on the build; this gates
 * them on accessibility the same way. Scans the full page — every tab panel
 * revealed, every collapsible/[hidden] region opened, live demos driven — in
 * both themes.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function killMotion(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*,*::before,*::after{transition:none!important;animation:none!important;scroll-behavior:auto!important}`,
  });
}

/** Reveal everything axe would otherwise skip: all tab panels, <details>, and
 *  any element hidden via the [hidden] attribute or a display-toggling class. */
async function revealAll(page: Page): Promise<void> {
  await page.evaluate(() => {
    // Expand any native disclosure widgets.
    for (const d of document.querySelectorAll('details')) d.open = true;
    // Show every tab panel simultaneously so their contents get scanned.
    for (const p of document.querySelectorAll<HTMLElement>('[role="tabpanel"]')) {
      p.hidden = false;
      p.removeAttribute('hidden');
    }
    // Un-hide anything else toggled off via the hidden attribute.
    for (const el of document.querySelectorAll<HTMLElement>('[hidden]')) {
      el.hidden = false;
      el.removeAttribute('hidden');
    }
  });
}

/** Click every "encrypt" / demo trigger so dynamically-rendered output (which
 *  is where contrast/aria regressions usually hide) is present when we scan. */
async function driveDemos(page: Page): Promise<void> {
  const triggers = page.locator(
    'button[id$="-encrypt-btn"], button.predict-reveal, button.quiz-check',
  );
  const count = await triggers.count();
  for (let i = 0; i < count; i++) {
    const btn = triggers.nth(i);
    if (await btn.isVisible().catch(() => false)) {
      await btn.click({ trial: false }).catch(() => {});
    }
  }
  // Let any async crypto output render.
  await page.waitForTimeout(300);
  // Re-reveal — a demo may have created fresh [hidden] output regions.
  await revealAll(page);
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await killMotion(page);
  await revealAll(page);
  await driveDemos(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await killMotion(page);
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await revealAll(page);
  await driveDemos(page);
  await scan(page);
});
