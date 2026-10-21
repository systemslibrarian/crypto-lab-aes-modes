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
  await expect(page.locator('#ofb-generation')).toHaveText('4 logical AES block evaluations during generation; 64 bytes prepared.');
  const message = '0123456789'.repeat(6);
  await page.locator('#ofb-plaintext').fill(message);
  await page.locator('#ofb-encrypt').click();
  await expect(page.locator('#ofb-xor-count')).toHaveText('0 logical AES block evaluations during XOR.');
  const pt = bytes(await read(page, 'plaintext-hex')), ct = bytes(await read(page, 'ciphertext'));
  expect(pt).toEqual(Buffer.from(message)); expect(ct.length).toBe(pt.length);
  expect(xor(ct, pt)).toEqual(bytes(blocks.join('')).subarray(0, pt.length));
  await expect(page.locator('#ofb-length')).toHaveText(`${pt.length} plaintext bytes → ${ct.length} OFB ciphertext bytes; CBC with PKCS#7: ${16 * (Math.floor(pt.length / 16) + 1)} bytes.`);
  for (const i of [1, 3, 4]) {
    await page.locator('#ofb-index').fill(String(i)); await page.locator('#ofb-access-btn').click();
    await expect(page.locator('.ofb-access-row')).toHaveCount(i);
    const expected = pt.subarray((i - 1) * 16, i * 16).toString('hex');
    await expect(page.locator('#ofb-access')).toContainText(`Block ${i}: OFB ${blocks.slice(0, i).length} logical AES block evaluations; CTR 1 logical AES block evaluation. OFB plaintext ${expected}; CTR plaintext ${expected}.`);
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
  test.setTimeout(120_000);
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

// CFB claims use AES-CTR as an independent raw AES-block oracle.
import { boot, scan } from './gate';
async function openCFB(page: Page) {
  await boot(page, 'dark');
  await page.locator('#tab-cfb').click();
  await expect(page.locator('#panel-cfb')).toBeVisible();
}
async function encryptCFB(page: Page, s = '128') {
  await page.locator('#cfb-segment').selectOption(s);
  await page.locator('#cfb-encrypt').click();
  await expect(page.locator('#cfb-length')).toContainText('Round trip: matches');
}

async function cfbDamage(page: Page, operation: { kind: 'delete'; index: number; count: number } | { kind: 'flip'; compare?: boolean }) {
  return page.evaluate(async (op) => {
    const read = (id: string) => document.getElementById(id)!.textContent!.trim();
    const h = (s: string) => Uint8Array.from((s.match(/../g) ?? []).map(x => parseInt(x, 16)));
    let raw: Uint8Array, iv: Uint8Array, pt: Uint8Array, ct: Uint8Array;
    let size: number, bit = 0;
    if (op.kind === 'delete') {
      raw = h(read('cfb-key')); iv = h(read('cfb-iv-output'));
      pt = h(read('cfb-plaintext-hex')); ct = h(read('cfb-ciphertext'));
      size = Number((document.getElementById('cfb-segment') as HTMLSelectElement).value) / 8;
    } else {
      const m = document.querySelector('.cfb-comparison-input')!.textContent!
        .match(/Key ([a-f0-9]+); IV ([a-f0-9]+); plaintext ([a-f0-9]+); bit (\d+)/)!;
      raw = h(m[1]); iv = h(m[2]); pt = h(m[3]); bit = Number(m[4]);
      size = 16; ct = new Uint8Array(); // Act 2 is CFB-128 regardless of the selector.
    }
    const ctr = await crypto.subtle.importKey('raw', raw as BufferSource, 'AES-CTR', false, ['encrypt']);
    const aes = async (input: Uint8Array) => new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-CTR', counter: input as BufferSource, length: 128 }, ctr, new Uint8Array(16)));
    // SP 800-38A: shift the register by s bits and append the ciphertext segment.
    const chain = async (data: Uint8Array, decrypt: boolean) => {
      let register: Uint8Array = iv.slice();
      const result = new Uint8Array(data.length);
      for (let start = 0; start < data.length; start += size) {
        const stream = await aes(register), length = Math.min(size, data.length - start);
        for (let j = 0; j < length; j++) result[start + j] = data[start + j] ^ stream[j];
        if (length === size) {
          const ciphertext = (decrypt ? data : result).slice(start, start + size);
          register = Uint8Array.from([...register.slice(size), ...ciphertext]);
        }
      }
      return result;
    };
    const comparison = (mode: string, original: Uint8Array, actual: Uint8Array) => {
      const root = op.kind === 'delete' ? '#cfb-delete-result' : '#cfb-flip-result';
      const nodes = [...document.querySelectorAll<HTMLElement>(`${root} [data-mode="${mode}"] [data-index]`)];
      return {
        mode,
        expected: [...actual.keys()].filter(i => actual[i] !== original[i]),
        shown: nodes.filter(e => e.dataset.changed === 'true').map(e => Number(e.dataset.index)),
        actual: [...actual], original: [...original],
        printed: nodes.map(e => parseInt(e.textContent!.match(/^\d+:([a-f0-9]{2})/)![1], 16)),
      };
    };
    if (op.kind === 'delete') {
      const remove = (data: Uint8Array) => Uint8Array.from([...data.slice(0, op.index), ...data.slice(op.index + op.count)]);
      return [comparison(`CFB-${size * 8}`, remove(pt), await chain(remove(ct), true))];
    }
    const flip = (data: Uint8Array) => { const result = data.slice(); result[bit >>> 3] ^= 1 << (bit & 7); return result; };
    ct = await chain(pt, false);
    const results = [comparison('CFB-128', pt, await chain(flip(ct), true))];
    if (op.compare) {
      const ofb = async (data: Uint8Array) => {
        let prev: Uint8Array = iv.slice(); const result = data.slice();
        for (let i = 0; i < data.length; i += 16) {
          prev = await aes(prev);
          for (let j = 0; j < 16 && i + j < data.length; j++) result[i + j] ^= prev[j];
        }
        return result;
      };
      results.push(comparison('OFB', pt, await ofb(flip(await ofb(pt)))));
      const cbc = await crypto.subtle.importKey('raw', raw as BufferSource, 'AES-CBC', false, ['encrypt', 'decrypt']);
      const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv: iv as BufferSource }, cbc, pt as BufferSource));
      const plaintext = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-CBC', iv: iv as BufferSource }, cbc, flip(ciphertext)));
      results.push(comparison('CBC', pt, plaintext));
    }
    return results;
  }, operation);
}

function assertCFBDamage(results: Awaited<ReturnType<typeof cfbDamage>>) {
  for (const result of results) {
    expect(result.expected.length, `${result.mode}: the damage must be non-empty`).toBeGreaterThan(0);
    expect(result.shown, `${result.mode}: changed indices`).toEqual(result.expected);
    expect(result.printed, `${result.mode}: plaintext bytes`).toEqual(result.actual);
  }
}

async function assertCFBLeak(page: Page) {
  const p1 = Buffer.from(await page.locator('#cfb-plaintext').inputValue());
  const p2 = Buffer.from(await page.locator('#cfb-plaintext2').inputValue());
  const overlap = Math.min(p1.length, p2.length);
  let first = 0;
  while (first < overlap && p1[first] === p2[first]) first++;
  const leak = first === overlap ? overlap : Math.min(overlap, 16 * (Math.floor(first / 16) + 1));
  await expect(page.locator('#cfb-reuse-result')).toContainText(`${leak} overlapping bytes recovered`);
  await expect(page.locator('.cfb-leak-block')).toHaveCount(Math.ceil(leak / 16));
  await expect(page.locator('#cfb-reuse-result')).toHaveClass('cfb-alarm');
}

async function assertCFBNegativeClaim(page: Page) {
  const result = page.locator('#cfb-gadget-result');
  await expect(result).toHaveAttribute('data-verdict', 'modified');
  await expect(result).toHaveClass('cfb-alarm');
  // §4.1d assertion 2: the actual mechanism must satisfy every displayed check.
  for (const check of ['decryption', 'length', 'chosen block', 'other blocks']) {
    await expect(result.locator(`[data-check="${check}"]`)).toHaveAttribute('data-verdict', 'pass');
  }
  await expect(result.locator('[data-verdict="pass"]')).toHaveCount(4);
  await expect(result.locator('[data-verdict="fail"]')).toHaveCount(0);
  await expect(result).toContainText('DECRYPTED — AND MODIFIED');
  await expect(result).toContainText('CFB-128 gives confidentiality only: anyone who knows one plaintext block');
  await expect(result.locator('.cfb-strip [data-block="0"]')).toHaveText('Block 0: chosen');
  await expect(result.locator('.cfb-strip [data-block="1"]')).toHaveText('Block 1: garbled');
}

test('CFB negative claim: all checks pass while known block is rewritten', async ({ page }) => {
  await openCFB(page); await page.locator('#cfb-rewrite').click(); await assertCFBNegativeClaim(page);
});

for (const [s, index, count, label] of [
  ['8', 7, 1, 'CFB-8 byte at k=7'],
  ['128', 5, 1, 'CFB-128 byte at k=5'],
  ['128', 16, 16, 'CFB-128 aligned block at k=16'],
] as const) {
  test(`CFB deletion independently recomputed: ${label}`, async ({ page }) => {
    await openCFB(page); await encryptCFB(page, s);
    await page.locator('#cfb-delete-index').fill(String(index));
    await page.locator(count === 16 ? '#cfb-delete-block' : '#cfb-delete-byte').click();
    await expect(page.locator('#cfb-delete-result .cfb-strip')).toBeVisible();
    const results = await cfbDamage(page, { kind: 'delete', index, count });
    assertCFBDamage(results);
    const { shown, actual } = results[0];
    await expect(page.locator('#cfb-delete-result strong')).toContainText(`${shown.length} changed bytes`);
    if (s === '8') expect(shown.every(i => i >= index && i <= index + 15)).toBe(true);
    else if (count === 16) expect([...new Set(shown.map(i => Math.floor(i / 16)))]).toEqual([1]);
    else {
      // Damage persists into every remaining block, including the last; individual bytes may match by chance.
      for (let block = Math.floor(index / 16); block < Math.ceil(actual.length / 16); block++) {
        expect(shown.some(i => Math.floor(i / 16) === block), `damaged block ${block}`).toBe(true);
      }
    }
  });
}

test('CFB comparison strip independently recomputed for CFB-128, CBC and OFB', async ({ page }) => {
  await openCFB(page); await page.locator('#cfb-bit').fill('135'); await page.locator('#cfb-flip').click();
  await expect(page.locator('.cfb-comparison-input')).toBeVisible();
  assertCFBDamage(await cfbDamage(page, { kind: 'flip', compare: true }));
});

test('CFB acts 2, 4 and 5 stay CFB-128 when s=8 is selected', async ({ page }) => {
  await openCFB(page); await page.locator('#cfb-segment').selectOption('8');
  await page.locator('#cfb-bit').fill('135'); await page.locator('#cfb-flip').click();
  await expect(page.locator('.cfb-comparison-input')).toBeVisible();
  assertCFBDamage(await cfbDamage(page, { kind: 'flip' }));
  await page.locator('#cfb-reuse').click(); await assertCFBLeak(page);
  await page.locator('#cfb-rewrite').click(); await assertCFBNegativeClaim(page);
});

test('CFB bad IV length fails closed', async ({ page }) => {
  await openCFB(page); await encryptCFB(page);
  await page.locator('#cfb-iv').fill('bad'); await page.locator('#cfb-encrypt').click();
  await expect(page.locator('#cfb-notice')).toContainText('IV must have 32 hexadecimal characters; found 3.');
  await expect(page.locator('#cfb-ciphertext')).toBeEmpty();
});
test('CFB all-zero IV in the main field fails closed', async ({ page }) => {
  await openCFB(page); await encryptCFB(page);
  await page.locator('#cfb-iv').fill('0'.repeat(32)); await page.locator('#cfb-encrypt').click();
  await expect(page.locator('#cfb-notice')).toContainText('All-zero IV refused');
  await expect(page.locator('#cfb-ciphertext')).toBeEmpty();
});
test('CFB empty plaintext has empty ciphertext and zero AES evaluations', async ({ page }) => {
  await openCFB(page); await page.locator('#cfb-plaintext').fill(''); await encryptCFB(page);
  await expect(page.locator('#cfb-length')).toContainText('0 plaintext bytes → 0 ciphertext bytes. 0 AES encryption evaluations to encrypt; 0 to decrypt.');
  await expect(page.locator('#cfb-length')).toContainText('Empty plaintext produces empty ciphertext.');
  await expect(page.locator('#cfb-ciphertext')).toBeEmpty();
  await expect(page.locator('.cfb-trace-row')).toHaveCount(0);
});
test('CFB last-block flip changes only the chosen bit in that block', async ({ page }) => {
  await openCFB(page); await page.locator('#cfb-plaintext').fill('0123456789abcdef'.repeat(4));
  const bit = 63 * 8 + 3;
  await page.locator('#cfb-bit').fill(String(bit)); await page.locator('#cfb-flip').click();
  await expect(page.locator('.cfb-comparison-input')).toContainText('Last block: no following block exists to garble.');
  const results = await cfbDamage(page, { kind: 'flip' }); assertCFBDamage(results);
  expect(results[0].shown).toEqual([63]);
  expect(results[0].printed[63] ^ results[0].original[63]).toBe(1 << 3);
});
test('CFB delete index out of range fails closed', async ({ page }) => {
  await openCFB(page); await encryptCFB(page, '8');
  const length = (await page.locator('#cfb-ciphertext').innerText()).trim().length / 2;
  await page.locator('#cfb-delete-index').fill(String(length)); await page.locator('#cfb-delete-byte').click();
  await expect(page.locator('#cfb-notice')).toContainText(`Choose a byte index from 0 to ${length - 1}.`);
  await expect(page.locator('#cfb-delete-result')).toBeEmpty();
});
test('CFB Zerologon cancel is neutral and incomplete', async ({ page }) => {
  await openCFB(page);
  const first = await page.evaluate(async () => {
    const raw = new Uint8Array(16), k = await crypto.subtle.importKey('raw', raw, 'AES-CTR', false, ['encrypt']);
    const first = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CTR', counter: raw, length: 128 }, k, raw))[0];
    // Fix only the first search key so a lucky immediate hit cannot race cancellation.
    const random = crypto.getRandomValues;
    crypto.getRandomValues = ((target: ArrayBufferView | null) => target instanceof Uint8Array && target.length === 16
      ? target.fill(0) : random.call(crypto, target)) as typeof crypto.getRandomValues;
    try {
      document.getElementById('cfb-search')!.click();
      document.getElementById('cfb-cancel')!.click();
    } finally { crypto.getRandomValues = random; }
    return first;
  });
  expect(first).not.toBe(0);
  const result = page.locator('#cfb-search-result');
  await expect(result).toHaveAttribute('data-verdict', 'cancelled');
  await expect(result).toHaveClass('cfb-output');
  await expect(result).toContainText('Incomplete');
  await expect(page.locator('#cfb-search')).toBeEnabled();
});
test('CFB wrong known block reports the failed chosen-block check', async ({ page }) => {
  await openCFB(page); await page.locator('#cfb-known').fill('NOT THE ORIGINAL'); await page.locator('#cfb-rewrite').click();
  const result = page.locator('#cfb-gadget-result');
  await expect(result).toContainText('typed known block is wrong');
  await expect(result.locator('[data-check="chosen block"]')).toHaveAttribute('data-verdict', 'fail');
  await expect(result.locator('.cfb-strip [data-block="0"]')).toHaveText('Block 0: differs from chosen');
});
test('CFB chosen block not 16 bytes fails closed', async ({ page }) => {
  await openCFB(page); await page.locator('#cfb-rewrite').click();
  await expect(page.locator('#cfb-gadget-result')).toHaveAttribute('data-verdict', 'modified');
  await page.locator('#cfb-chosen').fill('short'); await page.locator('#cfb-rewrite').click();
  await expect(page.locator('#cfb-notice')).toContainText('Known and chosen blocks must each be 16 bytes; found 16 and 5.');
  await expect(page.locator('#cfb-gadget-result')).not.toHaveAttribute('data-verdict');
  await expect(page.locator('#cfb-gadget-result [data-check]')).toHaveCount(0);
});

for (const [field, replacement, title] of [
  ['size', '256', 'CFB key-size change retires results; re-selecting the same size is a no-op'],
  ['iv', '0102030405060708090a0b0c0d0e0f10', 'CFB IV change retires results; re-entering the same IV is a no-op'],
  ['segment', '8', 'CFB segment change retires results; re-selecting the same segment is a no-op'],
] as const) {
  test(title, async ({ page }) => {
    await openCFB(page); await encryptCFB(page);
    for (const [button, output] of [['flip', 'flip-result'], ['delete-byte', 'delete-result'], ['reuse', 'reuse-result'], ['rewrite', 'gadget-result']]) {
      await page.locator(`#cfb-${button}`).click(); await expect(page.locator(`#cfb-${output}`)).not.toBeEmpty();
    }
    const ids = ['trace', 'ciphertext', 'plaintext-hex', 'iv-output', 'length', 'decrypt-inputs', 'math', 'flip-result', 'delete-result', 'reuse-result', 'gadget-result'];
    const before = await Promise.all(ids.map(id => page.locator(`#cfb-${id}`).textContent()));
    const notice = await page.locator('#cfb-notice').textContent(), input = page.locator(`#cfb-${field}`), same = await input.inputValue();
    if (field === 'iv') { await input.fill(same); await input.dispatchEvent('input'); await input.dispatchEvent('change'); }
    else await input.selectOption(same);
    expect(await Promise.all(ids.map(id => page.locator(`#cfb-${id}`).textContent()))).toEqual(before);
    await expect(page.locator('#cfb-notice')).toHaveText(notice!);
    if (field === 'iv') await input.fill(replacement); else await input.selectOption(replacement);
    for (const id of ids) await expect(page.locator(`#cfb-${id}`)).toBeEmpty();
    await expect(page.locator('#cfb-notice')).toContainText('previous CFB results retired');
    for (const id of ['reuse-result', 'gadget-result']) {
      await expect(page.locator(`#cfb-${id}`)).not.toHaveAttribute('data-verdict');
      await expect(page.locator(`#cfb-${id}`)).toHaveClass('cfb-output');
    }
    if (field === 'size') await expect(page.locator('#cfb-key')).toBeEmpty();
  });
}

test('CFB chosen equals known gives an unchanged non-alarm verdict', async ({ page }) => {
  await openCFB(page); await page.locator('#cfb-rewrite').click(); await assertCFBNegativeClaim(page);
  await page.locator('#cfb-chosen').fill(await page.locator('#cfb-known').inputValue());
  await page.locator('#cfb-rewrite').click();
  const result = page.locator('#cfb-gadget-result');
  await expect(result).toHaveAttribute('data-verdict', 'unchanged');
  await expect(result).toHaveClass('cfb-output');
  await expect(result).toContainText('Nothing changed');
  await expect(result).not.toContainText('DECRYPTED — AND MODIFIED');
  await expect(result).not.toContainText('garbled');
  await expect(result.locator('[data-verdict="pass"]')).toHaveCount(4);
  await expect(result.locator('[data-changed="true"]')).toHaveCount(0);
  await expect(result.locator('.cfb-strip [data-block="0"]')).toHaveText('Block 0: chosen, unchanged');
  await expect(result.locator('.cfb-strip [data-block="1"]')).toHaveText('Block 1: unchanged');
});

test('CFB IV reuse prefix matches actual first differing block', async ({ page }) => {
  await openCFB(page); await page.locator('#cfb-reuse').click(); await assertCFBLeak(page);
});
test('CFB identical overlapping plaintext leaks the whole overlap', async ({ page }) => {
  await openCFB(page);
  // Different lengths with an identical UTF-8 prefix also have no differing byte in the overlap.
  await page.locator('#cfb-plaintext').fill('same é message with a longer tail');
  await page.locator('#cfb-plaintext2').fill('same é message');
  await page.locator('#cfb-reuse').click(); await assertCFBLeak(page);
  const n = Buffer.byteLength(await page.locator('#cfb-plaintext2').inputValue());
  await expect(page.locator('#cfb-reuse-result')).toContainText(`Identical over the overlap: the whole ${n}-byte overlap leaks`);
  await expect(page.locator('#cfb-reuse-result')).not.toContainText('first differing block');
});
test('CFB mirror-image CBC button opens the CBC tab', async ({ page }) => {
  await openCFB(page); await page.locator('#cfb-cbc-link').click();
  await expect(page.locator('#panel-cbc')).toBeVisible();
  await expect(page.locator('#tab-cbc')).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator('#tab-cbc')).toBeFocused();
  await expect(page.locator('#panel-cfb')).toBeHidden();
});

for(const s of ['128','8'])test(`CFB-${s} printed chain independently recomputed with AES-CTR`,async({page})=>{
 await openCFB(page);await encryptCFB(page,s);
 const r=await page.evaluate(async()=>{const read=(id:string)=>document.getElementById(id)!.textContent!.trim(),h=(s:string)=>Uint8Array.from((s.match(/../g)??[]).map(x=>parseInt(x,16))),hex=(a:Uint8Array)=>[...a].map(x=>x.toString(16).padStart(2,'0')).join('');const raw=h(read('cfb-key')),iv=h(read('cfb-iv-output')),p=h(read('cfb-plaintext-hex')),c=h(read('cfb-ciphertext')),size=Number((document.getElementById('cfb-segment') as HTMLSelectElement).value)/8,key=await crypto.subtle.importKey('raw',raw,'AES-CTR',false,['encrypt']);const rows=[...document.querySelectorAll<HTMLElement>('.cfb-trace-row')];const errors:string[]=[];let reg:Uint8Array=iv;for(let i=0;i<rows.length;i++){const out=new Uint8Array(await crypto.subtle.encrypt({name:'AES-CTR',counter:reg as BufferSource,length:128},key,new Uint8Array(16)));if(rows[i].dataset.input!==hex(reg)||rows[i].dataset.output!==hex(out))errors.push(`AES row ${i}`);const seg=c.slice(i*size,(i+1)*size);if(rows[i].dataset.ct!==hex(seg))errors.push('cipher');for(let j=0;j<seg.length;j++)if((seg[j]^p[i*size+j])!==out[j])errors.push('XOR');reg=Uint8Array.from([...reg.slice(size),...seg]);}return {errors,rows:rows.length,expected:Math.ceil(p.length/size),length:c.length,plain:p.length};});expect(r.errors).toEqual([]);expect(r.rows).toBe(r.expected);expect(r.length).toBe(r.plain);
});

test('CFB zero-IV hit is independently checked, with alarm verdict',async({page})=>{await openCFB(page);await page.locator('#cfb-search').click();await expect(page.locator('#cfb-search-result')).toHaveAttribute('data-verdict','hit',{timeout:30000});await expect(page.locator('#cfb-search-result')).toHaveClass('cfb-alarm');const first=await page.evaluate(async()=>{const text=document.getElementById('cfb-search-result')!.textContent!,raw=Uint8Array.from(text.match(/Key ([a-f0-9]+);/)![1].match(/../g)!.map(x=>parseInt(x,16))),k=await crypto.subtle.importKey('raw',raw,'AES-CTR',false,['encrypt']);return new Uint8Array(await crypto.subtle.encrypt({name:'AES-CTR',counter:new Uint8Array(16),length:128},k,new Uint8Array(16)))[0];});expect(first).toBe(0);});

for(const width of [1280,320])test(`CFB accessible new states ${width}px`,async({page,browserName})=>{test.skip(browserName !== 'chromium', 'The scan gate runs in Chromium; functional claims run in every engine.');test.setTimeout(300000);await openCFB(page);await page.setViewportSize({width,height:900});await encryptCFB(page);await scan(page,`CFB encrypted ${width}`);await page.locator('#cfb-flip').click();await expect(page.locator('#cfb-flip-result')).not.toBeEmpty();await scan(page,`CFB flipped ${width}`);await encryptCFB(page,'8');await page.locator('#cfb-delete-byte').click();await scan(page,`CFB deleted ${width}`);await page.locator('#cfb-reuse').click();await scan(page,`CFB reuse ${width}`);await page.locator('#cfb-rewrite').click();await scan(page,`CFB gadget ${width}`);await page.locator('#cfb-search').click();await expect(page.locator('#cfb-search-result')).not.toBeEmpty({timeout:30000});await scan(page,`CFB zero IV ${width}`);});
