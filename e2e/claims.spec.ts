import { test, expect, type Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

async function open(page: Page) { await page.goto('./'); await page.locator('#tab-ofb').click(); }
async function read(page: Page, id: string) { return (await page.locator(`#ofb-${id}`).textContent())!.trim(); }
const bytes = (s: string) => Buffer.from(s, 'hex');
const xor = (a: Buffer, b: Buffer) => Buffer.from(a.map((v, i) => v ^ b[i]));

test('OFB precomputation, measured access and unpadded length match independent AES-CTR', async ({ page }) => {
  await open(page);
  // Generation happens while the plaintext is still empty.
  await page.locator('#ofb-generate').click();
  await expect(page.locator('#ofb-stream code')).toHaveCount(4);
  const blocks = await page.locator('#ofb-stream code').allTextContents();
  const key = await read(page, 'key'), iv = await read(page, 'iv-output');
  const independent = await page.evaluate(async ({ key, iv }) => {
    const h = (s: string) => new Uint8Array(s.match(/../g)!.map(x => parseInt(x, 16)));
    const k = await crypto.subtle.importKey('raw', h(key), 'AES-CTR', false, ['encrypt']);
    let counter = h(iv); const values: string[] = [];
    for (let i = 0; i < 4; i++) {
      counter = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CTR', counter, length: 128 }, k, new Uint8Array(16)));
      values.push(Array.from(counter, n => n.toString(16).padStart(2, '0')).join(''));
    }
    return values;
  }, { key, iv });
  expect(blocks).toEqual(independent);
  await expect(page.locator('#ofb-generation')).toHaveText('4 AES evaluations during generation; 64 bytes prepared.');
  const message = '0123456789'.repeat(6);
  await page.locator('#ofb-plaintext').fill(message);
  await page.locator('#ofb-encrypt').click();
  await expect(page.locator('#ofb-xor-count')).toHaveText('0 AES evaluations during XOR.');
  const pt = bytes(await read(page, 'plaintext-hex')), ct = bytes(await read(page, 'ciphertext'));
  expect(pt).toEqual(Buffer.from(message)); expect(ct.length).toBe(pt.length);
  expect(xor(ct, pt)).toEqual(bytes(blocks.join('')).subarray(0, pt.length));
  await expect(page.locator('#ofb-length')).toHaveText(`${pt.length} plaintext bytes → ${ct.length} OFB ciphertext bytes; CBC with PKCS#7: ${16 * (Math.floor(pt.length / 16) + 1)} bytes.`);
  for (const i of [1, 3, 4]) {
    await page.locator('#ofb-index').fill(String(i)); await page.locator('#ofb-access-btn').click();
    await expect(page.locator('.ofb-access-row')).toHaveCount(i);
    const expected = pt.subarray((i - 1) * 16, i * 16).toString('hex');
    await expect(page.locator('#ofb-access')).toContainText(`Block ${i}: OFB ${blocks.slice(0, i).length} AES evaluations; CTR 1 AES evaluation. OFB plaintext ${expected}; CTR plaintext ${expected}.`);
  }
  // Each normal encryption consumes a distinct IV; a no-op size selection preserves prepared material.
  await page.locator('#ofb-encrypt').click(); await expect(page.locator('#ofb-iv-output')).not.toHaveText(iv);
  const next = await read(page, 'iv-output');
  await page.locator('#ofb-size').dispatchEvent('change'); await expect(page.locator('#ofb-iv-output')).toHaveText(next);
  await expect(page.locator('#ofb-stream code')).toHaveCount(4);
  await page.locator('#ofb-size').selectOption('256');
  await expect(page.locator('#ofb-stream')).toBeEmpty(); await expect(page.locator('#ofb-ciphertext')).toBeEmpty();
  await expect(page.locator('#ofb-notice')).toContainText('Key size changed');
});

test('OFB IV reuse exposes only the overlapping second plaintext', async ({ page }) => {
  await open(page);
  for (const [a, b] of [['known', 'hidden message with a longer tail'], ['long enough known message', 'short']]) {
    await page.locator('#ofb-plaintext').fill(a); await page.locator('#ofb-plaintext2').fill(b); await page.locator('#ofb-reuse').click();
    const out = await read(page, 'attack'), extract = (label: string) => bytes(out.match(new RegExp(`${label}: ([0-9a-f]*)`))![1]);
    const c1 = extract('C₁'), c2 = extract('C₂'), n = Math.min(Buffer.byteLength(a), Buffer.byteLength(b));
    expect(c1.length).toBe(Buffer.byteLength(a)); expect(c2.length).toBe(Buffer.byteLength(b));
    const common = xor(c1.subarray(0, n), c2.subarray(0, n));
    expect(extract('C₁ ⊕ C₂')).toEqual(common);
    expect(common).toEqual(xor(Buffer.from(a).subarray(0, n), Buffer.from(b).subarray(0, n)));
    expect(extract('Recovered hex')).toEqual(Buffer.from(b).subarray(0, n));
    expect(out).toContain(`${n} of ${Buffer.byteLength(b)} bytes`);
    await expect(page.locator('#ofb-attack')).toHaveClass('ofb-alarm');
  }
  await page.locator('#ofb-plaintext2').fill('new'); await expect(page.locator('#ofb-attack')).toBeEmpty();
});

test('OFB negative claim: valid decryption and matching length still allow an attacker modification', async ({ page }) => {
  await open(page); await page.locator('#ofb-preset').click();
  const result = page.locator('#ofb-modified');
  await expect(result).toHaveAttribute('data-verdict', 'modified'); await expect(result).toHaveClass('ofb-alarm');
  const out = await read(page, 'modified');
  expect(out).toContain('PAY 9100'); expect(out).toContain('8 bytes retained; decryption completed without an error.');
  const mask = xor(Buffer.from('PAY 0100'), Buffer.from('PAY 9100'));
  const original = bytes(out.match(/Original ciphertext: ([\da-f]+)/)![1]);
  const modified = bytes(out.match(/Modified ciphertext: ([\da-f]+)/)![1]);
  expect(xor(original, modified)).toEqual(mask);
  const changed = [...mask].reduce((n, v) => n + v.toString(2).replace(/0/g, '').length, 0);
  expect(out).toContain(`${changed} plaintext bits changed`);
  expect(out).toContain('Plaintext hex: '+Buffer.from('PAY 9100').toString('hex'));
  expect(out).toContain('DECRYPTED — AND MODIFIED');
  expect(out).toContain('OFB gives confidentiality only: a modified ciphertext decrypts without any error, to a plaintext the attacker changed bit for bit.');
  await page.locator('#ofb-sixty').click(); await page.locator('#ofb-bit').fill('9'); await page.locator('#ofb-flip').click();
  await expect(result).toContainText('1 plaintext bits changed; 60 bytes retained');
});

test('OFB input errors, empty message and result retirement are honest', async ({ page }) => {
  await open(page); await page.locator('#ofb-iv').fill('00'); await page.locator('#ofb-generate').click();
  await expect(page.locator('#ofb-notice')).toContainText('found 2'); await expect(page.locator('#ofb-encrypt')).toBeDisabled();
  await page.locator('#ofb-new-iv').click(); await page.locator('#ofb-generate').click(); await page.locator('#ofb-encrypt').click();
  await expect(page.locator('#ofb-length')).toContainText('0 plaintext bytes → 0 OFB ciphertext bytes; CBC with PKCS#7: 16 bytes. Empty plaintext');
  await page.locator('#ofb-sixty').click(); await page.locator('#ofb-index').fill('5'); await page.locator('#ofb-access-btn').click();
  await expect(page.locator('#ofb-notice')).toContainText('1–4');
  await page.locator('#ofb-plaintext').fill('edited'); await expect(page.locator('#ofb-ciphertext')).toBeEmpty();
  await expect(page.locator('#ofb-access-btn')).toBeDisabled();
});

test('OFB all new states have no WCAG A/AA violations or horizontal overflow at 320px', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 900 }); await open(page);
  const scan = async () => {
    const result = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze();
    expect(result.violations).toEqual([]);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  };
  await scan(); await page.locator('#ofb-sixty').click(); await scan();
  await page.locator('#ofb-access-btn').click(); await scan();
  await page.locator('#ofb-reuse').click(); await scan();
  await page.locator('#ofb-preset').click(); await scan();
  await page.locator('#ofb-iv').fill('bad'); await page.locator('#ofb-generate').click(); await scan();
});
