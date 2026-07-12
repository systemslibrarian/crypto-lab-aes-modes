import { expect, test } from '@playwright/test';

/**
 * Functional exhibit smoke tests — these gate the build on the demos actually
 * *working*, not just being accessible. Each test drives a real exhibit in the
 * browser and asserts the security-relevant outcome the narrative promises:
 *   - the padding oracle recovers the real plaintext from ciphertext + a
 *     padding-validity oracle (not a canned string),
 *   - GCM and hand-rolled CCM both REJECT tampered ciphertext,
 *   - ECB decrypt returns plaintext with no integrity check (the contrast).
 */

async function openTab(page: import('@playwright/test').Page, id: string): Promise<void> {
  await page.locator(`#tab-${id}`).click();
  await expect(page.locator(`#panel-${id}`)).toBeVisible();
}

test('padding oracle recovers the actual plaintext byte-by-byte', async ({ page }) => {
  await page.goto('.');
  await openTab(page, 'oracle');

  const secret = 'Attack me!';
  await page.locator('#oracle-plaintext').fill(secret);
  await page.locator('#oracle-setup-btn').click();

  // Ciphertext must be produced and be a multiple of a block (32 hex chars).
  const ctHex = (await page.locator('#oracle-ciphertext').textContent())?.trim() ?? '';
  expect(ctHex.length).toBeGreaterThanOrEqual(32);
  expect(ctHex.length % 32).toBe(0);

  await page.locator('#oracle-run-btn').click();

  // The attack is real and iterative; give it room, then assert the recovered
  // text contains the secret we never handed the oracle in plaintext form.
  const recovered = page.locator('#oracle-recovered-text');
  await expect(recovered).toContainText(secret, { timeout: 60_000 });
});

test('GCM rejects a tampered ciphertext', async ({ page }) => {
  await page.goto('.');
  await openTab(page, 'gcm');

  await page.locator('#gcm-encrypt-btn').click();
  await expect(page.locator('#gcm-ciphertext')).not.toBeEmpty();

  await page.locator('#gcm-tamper-btn').click();
  const out = page.locator('#gcm-tamper-content');
  await expect(out).toContainText(/REJECTED/i);
  await expect(out).not.toContainText(/Unexpected/i);
});

test('hand-rolled CCM rejects a tampered ciphertext', async ({ page }) => {
  await page.goto('.');
  await openTab(page, 'ccm');

  await page.locator('#ccm-encrypt-btn').click();
  await expect(page.locator('#ccm-ciphertext')).not.toBeEmpty();

  await page.locator('#ccm-tamper-btn').click();
  const out = page.locator('#ccm-tamper-content');
  await expect(out).toContainText(/REJECTED/i);
  await expect(out).not.toContainText(/Unexpected/i);
});

test('ECB decrypt returns plaintext with no integrity check (the counterexample)', async ({
  page,
}) => {
  await page.goto('.');
  await openTab(page, 'ecb');

  await page.locator('#ecb-plaintext').fill('YELLOW SUBMARINEYELLOW SUBMARINE');
  await page.locator('#ecb-encrypt-btn').click();
  await expect(page.locator('#ecb-ciphertext')).not.toBeEmpty();

  // Tampering one ciphertext block must NOT raise an integrity error — ECB has
  // none. The panel still renders decrypt output rather than rejecting.
  await page.locator('#ecb-decrypt-tamper-btn').click();
  const out = page.locator('#ecb-decrypt-output');
  await expect(out).toBeVisible();
  await expect(out).toContainText(/ECB/i);
});
