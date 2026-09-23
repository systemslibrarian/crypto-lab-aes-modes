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

test('forbidden attack: nonce reuse lets WebCrypto accept a forged ciphertext', async ({
  page,
}) => {
  await page.goto('.');
  await openTab(page, 'gcm');

  // Reuse the nonce → recover H → forge. The REAL WebCrypto AES-GCM verifier
  // must accept the forged (ciphertext, tag) and return the attacker's text.
  await page.locator('#forbidden-run-btn').click();
  const out = page.locator('#forbidden-output');
  await expect(out).toBeVisible();
  await expect(out.locator('[data-verdict="accepted"]')).toBeVisible();
  await expect(out).toContainText(/ACCEPTED the forgery/i);
  await expect(out).toContainText('PAY EVE $10000!!');
});

test('forbidden attack control: a fresh nonce makes WebCrypto REJECT the forgery', async ({
  page,
}) => {
  await page.goto('.');
  await openTab(page, 'gcm');

  await page.locator('#forbidden-control-btn').click();
  const out = page.locator('#forbidden-output');
  await expect(out).toBeVisible();
  await expect(out.locator('[data-verdict="rejected"]')).toBeVisible();
  await expect(out).toContainText(/REJECTED the forgery/i);
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

/**
 * Two label regressions, both found by re-deriving the teaching notes against the
 * live page rather than by a test failing.
 *
 * The first is the defect CLASS, not the instance: the targeted bit-flip demo
 * explains which ciphertext byte it flips, and prints which byte it flipped, and
 * those two sentences had drifted apart — the explanation said C₀[7], the code
 * flipped index 7, and the result line said C₀[1]. Asserting "the result line says
 * 7" would pin the instance; asserting that the two sentences name the SAME index
 * catches the next drift in either direction, which is what actually went wrong.
 */
test('the targeted bit-flip demo names one byte, not two', async ({ page }) => {
  await page.goto('.');
  await openTab(page, 'cbc');
  await page.locator('#cbc-encrypt-btn').click();
  await page.locator('#cbc-targeted-btn').click();
  const body = (await page.locator('#panel-cbc').innerText()).replace(/\s+/g, ' ');

  const explained = /we flip bit 0 of C₀\[(\d+)\]/.exec(body);
  const reported = /After flipping bit 0 of C₀\[(\d+)\]/.exec(body);
  expect(explained, 'the demo must explain which ciphertext byte it flips').not.toBeNull();
  expect(reported, 'the demo must report which ciphertext byte it flipped').not.toBeNull();
  expect(
    reported![1],
    `the explanation flips C₀[${explained![1]}] and the result line reports C₀[${reported![1]}]; `
      + 'a reader cannot tell which byte the attack used',
  ).toBe(explained![1]);

  // And the byte named is the one the attack needs: P₁[7] is the '0' in ";admin=0".
  expect(explained![1], 'the flip must target the byte holding the 0 in ";admin=0"').toBe('7');
  await expect(page.locator('#panel-cbc')).toContainText('admin=1');
});

/**
 * The second: recovering H from a reused nonce forges under THAT nonce. The tag is
 * GHASH_H(…) ⊕ E_K(J0), and J0 moves with the nonce, so H alone does not forge under
 * a fresh one. The self-check used to mark "can forge any future message under that
 * key" correct, which reaches past the forgery the lab actually builds.
 */
test('the GCM self-check does not overstate what a reused nonce buys', async ({ page }) => {
  await page.goto('.');
  await openTab(page, 'gcm');
  const panel = page.locator('#panel-gcm');
  const text = (await panel.innerText()).replace(/\s+/g, ' ');
  expect(text, 'the answer must not promise forgery beyond the reused nonce')
    .not.toContain('forge any future message under that key');
  expect(text).toContain('forge further messages under that nonce');

  const why = await panel.locator('[data-why-correct]').first().getAttribute('data-why-correct');
  expect(why, 'the explanation must not promise forgery under any ciphertext for the key')
    .not.toContain('forge any ciphertext under that key');
  expect(why, 'and it must say why a fresh nonce is not forgeable from H alone').toContain('E_K(J0)');
});
