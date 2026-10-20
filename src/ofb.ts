import { ecbEncryptBlock, exportKeyHex } from './ecb';
import { aesEncrypt, hexDecode, hexEncode, textToBytes } from './ui';
import { xor, ofbMath, renderMath } from './helpers';
import { reuseOFB } from './ofbBroken';

export interface EvaluationCounter { calls: number; trace?: { input: string; output: string }[] }
async function block(key: CryptoKey, input: Uint8Array, counter?: EvaluationCounter): Promise<Uint8Array> {
  if (counter) counter.calls++;
  const output = await ecbEncryptBlock(key, input);
  counter?.trace?.push({ input: hexEncode(input), output: hexEncode(output) });
  return output;
}
export async function ofbKeystream(key: CryptoKey, iv: Uint8Array, blocks: number, counter?: EvaluationCounter): Promise<Uint8Array> {
  if (iv.length !== 16) throw new Error(`IV must be 16 bytes; found ${iv.length}.`);
  if (!Number.isInteger(blocks) || blocks < 0) throw new Error('Block count must be a nonnegative integer.');
  const stream = new Uint8Array(blocks * 16);
  let previous: Uint8Array = iv.slice();
  for (let i = 0; i < blocks; i++) {
    previous = await block(key, previous, counter);
    stream.set(previous, i * 16);
  }
  return stream;
}
// [extension] point: CFB would feed ciphertext back here. OFB feeds AES output.
export async function ofbXor(key: CryptoKey, iv: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  return xor(data, await ofbKeystream(key, iv, Math.ceil(data.length / 16)));
}
export async function ofbDecryptBlock(key: CryptoKey, iv: Uint8Array, ct: Uint8Array, i: number, counter?: EvaluationCounter): Promise<Uint8Array> {
  const n = Math.ceil(ct.length / 16);
  if (!Number.isInteger(i) || i < 1 || i > n) throw new Error(`Block index must be in 1–${n}; found ${i}.`);
  const stream = await ofbKeystream(key, iv, i, counter);
  return xor(ct.slice((i - 1) * 16, i * 16), stream.slice((i - 1) * 16));
}
export async function ctrDecryptBlock(key: CryptoKey, initial: Uint8Array, ct: Uint8Array, i: number, counter?: EvaluationCounter): Promise<Uint8Array> {
  if (!Number.isInteger(i) || i < 1 || i > Math.ceil(ct.length / 16)) throw new Error('CTR block index out of range.');
  const input = initial.slice();
  const view = new DataView(input.buffer);
  view.setUint32(12, (view.getUint32(12) + i - 1) >>> 0);
  return xor(ct.slice((i - 1) * 16, i * 16), await block(key, input, counter));
}
const readable = (data: Uint8Array) => new TextDecoder().decode(data).replace(/\uFFFD/g, '·');

export function mountOFBPanel(): void {
  const panel = document.getElementById('panel-ofb');
  if (!panel) return;
  const el = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(`ofb-${id}`) as T;
  const val = (id: string) => el<HTMLInputElement>(id).value;
  const put = (id: string, text: string) => { el(id).textContent = text; };
  const freshIV = () => crypto.getRandomValues(new Uint8Array(16));
  el<HTMLInputElement>('iv').value = hexEncode(freshIV());
  let key: CryptoKey | undefined, size = val('size'), epoch = 0;
  let prepared: { iv: Uint8Array; stream: Uint8Array; counter: EvaluationCounter; used: boolean } | undefined;
  let record: { iv: Uint8Array; pt: Uint8Array; ct: Uint8Array } | undefined;
  const usedIVs = new Set<string>();
  function retire(why: string, clearStream = true) {
    epoch++;
    if (clearStream) { prepared = undefined; put('stream', ''); put('generation', ''); }
    record = undefined;
    for (const id of ['ciphertext', 'plaintext-hex', 'length', 'xor-count', 'access', 'attack', 'modified', 'math']) put(id, '');
    el('encrypt').toggleAttribute('disabled', !prepared);
    for (const id of ['access-btn', 'flip']) el(id).setAttribute('disabled', '');
    el('bits').querySelectorAll('button').forEach(button => { button.disabled = true; });
    for (const id of ['attack', 'modified']) { el(id).className = 'ofb-output'; delete el(id).dataset.verdict; }
    put('notice', why);
  }
  async function getKey() {
    if (key) return key;
    const requestedSize = size, version = epoch;
    const generated = await crypto.subtle.generateKey({ name: 'AES-CBC', length: Number(requestedSize) }, true, ['encrypt', 'decrypt']);
    if (size === requestedSize && epoch === version) key = generated;
    return generated;
  }
  function ivInput() {
    const h = val('iv').trim();
    if (!/^[\da-f]{32}$/i.test(h)) throw new Error(`IV must contain exactly 32 hexadecimal characters; found ${h.length}.`);
    return hexDecode(h);
  }
  async function generate() {
    retire('');
    const n = Number(val('blocks'));
    if (!Number.isInteger(n) || n < 1 || n > 128) throw new Error('Choose 1–128 keystream blocks.');
    let iv = ivInput();
    if (usedIVs.has(hexEncode(iv))) iv = freshIV();
    el<HTMLInputElement>('iv').value = hexEncode(iv);
    const version = epoch, k = await getKey(), counter = { calls: 0 };
    const stream = await ofbKeystream(k, iv, n, counter);
    if (version !== epoch) return;
    prepared = { iv, stream, counter, used: false };
    put('key', await exportKeyHex(k)); put('iv-output', hexEncode(iv));
    const rows = el('stream'); rows.replaceChildren();
    for (let i = 0; i < n; i++) {
      const row = document.createElement('div'); row.className = 'ofb-stream-row';
      const label = document.createElement('strong'); label.textContent = `y${i + 1} = AES(y${i}) → `;
      const code = document.createElement('code'); code.textContent = hexEncode(stream.slice(i * 16, i * 16 + 16));
      row.append(label, code); rows.append(row);
    }
    put('generation', `${counter.calls} AES evaluations during generation; ${stream.length} bytes prepared.`);
    el('encrypt').removeAttribute('disabled');
  }
  async function encrypt() {
    if (!prepared || prepared.used) await generate();
    if (!prepared) return;
    const session = prepared, version = epoch;
    const pt = textToBytes(val('plaintext'));
    if (pt.length > session.stream.length) throw new Error(`Prepare at least ${Math.ceil(pt.length / 16)} blocks for these ${pt.length} bytes.`);
    const before = session.counter.calls;
    const ct = xor(pt, session.stream);
    const during = session.counter.calls - before;
    const cbc = new Uint8Array(await aesEncrypt({ name: 'AES-CBC', iv: session.iv }, await getKey(), pt));
    if (version !== epoch) return;
    record = { iv: session.iv, pt, ct }; session.used = true; usedIVs.add(hexEncode(session.iv));
    put('plaintext-hex', hexEncode(pt)); put('ciphertext', hexEncode(ct));
    put('xor-count', `${during} AES evaluations during XOR.`);
    put('length', `${pt.length} plaintext bytes → ${ct.length} OFB ciphertext bytes; CBC with PKCS#7: ${cbc.length} bytes.${pt.length ? '' : ' Empty plaintext gives empty OFB ciphertext.'}`);
    renderMath(el('math'), ofbMath(session.iv, session.stream, pt, ct));
    for (const id of ['access-btn', 'flip']) el(id).toggleAttribute('disabled', ct.length === 0);
    el('bits').querySelectorAll('button').forEach(button => { button.disabled = ct.length === 0; });
    put('notice', 'This IV is now spent. Another encryption prepares a fresh random IV.');
  }
  function action(id: string, fn: () => Promise<void> | void) {
    el(id).addEventListener('click', async () => {
      const button = el<HTMLButtonElement>(id); button.disabled = true;
      try { await fn(); } catch (error) { put('notice', (error as Error).message); }
      finally { button.disabled = (id === 'encrypt' && !prepared) || (['access-btn', 'flip'].includes(id) && !record?.ct.length); }
    });
  }
  el('cbc-link').addEventListener('click', () => document.getElementById('tab-cbc')?.click());
  action('generate', generate); action('encrypt', encrypt);
  action('new-iv', () => { retire('New IV: previous keystream and results retired.'); el<HTMLInputElement>('iv').value = hexEncode(freshIV()); });
  el('size').addEventListener('change', () => {
    if (size === val('size')) return;
    size = val('size'); key = undefined; usedIVs.clear(); put('key', '');
    retire('Key size changed: previous key, keystream and results retired.');
    el<HTMLInputElement>('iv').value = hexEncode(freshIV());
  });
  for (const id of ['iv', 'blocks']) el(id).addEventListener('input', () => retire('Keystream settings changed: generate again.'));
  el('plaintext').addEventListener('input', () => retire('Plaintext changed: ciphertext retired.', false));
  el('plaintext2').addEventListener('input', () => { epoch++; put('attack', ''); });
  el('index').addEventListener('input', () => put('access', ''));
  action('sixty', async () => { el<HTMLTextAreaElement>('plaintext').value = '0123456789'.repeat(6); el<HTMLInputElement>('blocks').value = '4'; await generate(); await encrypt(); });
  action('access-btn', async () => {
    if (!record) return;
    const r = record, i = Number(val('index')), version = epoch, a: EvaluationCounter = { calls: 0, trace: [] }, b = { calls: 0 }, k = await getKey();
    const plain = await ofbDecryptBlock(k, r.iv, r.ct, i, a);
    const counter = r.iv.slice(); counter.fill(0, 12); counter[15] = 1;
    const raw = await crypto.subtle.exportKey('raw', k);
    const ctrKey = await crypto.subtle.importKey('raw', raw, 'AES-CTR', false, ['encrypt']);
    const ctrCt = new Uint8Array(await aesEncrypt({ name: 'AES-CTR', counter, length: 32 }, ctrKey, r.pt));
    const ctrPlain = await ctrDecryptBlock(k, counter, ctrCt, i, b);
    if (version !== epoch) return;
    put('access', `Block ${i}: OFB ${a.calls} AES evaluations; CTR ${b.calls} AES evaluation. OFB plaintext ${hexEncode(plain)}; CTR plaintext ${hexEncode(ctrPlain)}. OFB traversed ${a.calls} feedback rows; CTR encrypted one independent counter.`);
    for (const step of a.trace!) {
      const row = document.createElement('div'); row.className = 'ofb-access-row';
      row.textContent = `AES(${step.input}) → ${step.output}`; el('access').append(row);
    }
  });
  action('reuse', async () => {
    const version = epoch, p1 = textToBytes(val('plaintext')), p2 = textToBytes(val('plaintext2'));
    const result = await reuseOFB(await getKey(), freshIV(), p1, p2);
    if (version !== epoch) return;
    el('attack').className = 'ofb-alarm';
    put('attack', `⚠ keystream reused — P₂ recovered. ${result.recovered.length} of ${p2.length} bytes: ${readable(result.recovered)}\nC₁: ${hexEncode(result.c1)}\nC₂: ${hexEncode(result.c2)}\nC₁ ⊕ C₂: ${hexEncode(xor(result.c1, result.c2))}\nP₁ ⊕ P₂: ${hexEncode(xor(p1, p2))}\nRecovered hex: ${hexEncode(result.recovered)}`);
  });
  async function showModified(pt: Uint8Array, ct: Uint8Array, modified: Uint8Array, iv: Uint8Array, version: number) {
    const plain = await ofbXor(await getKey(), iv, modified);
    if (version !== epoch) return;
    let changed = 0;
    for (let i = 0; i < pt.length; i++) { let n = pt[i] ^ plain[i]; while (n) { changed += n & 1; n >>>= 1; } }
    el('modified').className = 'ofb-alarm';
    el('modified').dataset.verdict = 'modified';
    put('modified', `⚠ DECRYPTED — AND MODIFIED\n${readable(plain)}\nOriginal ciphertext: ${hexEncode(ct)}\nModified ciphertext: ${hexEncode(modified)}\nPlaintext hex: ${hexEncode(plain)}\n${changed} plaintext bits changed; ${plain.length} bytes retained; decryption completed without an error.\nOFB gives confidentiality only: a modified ciphertext decrypts without any error, to a plaintext the attacker changed bit for bit.`);
  }
  action('flip', async () => {
    if (!record) return;
    const j = Number(val('bit')), r = record;
    if (!Number.isInteger(j) || j < 0 || j >= r.ct.length * 8) throw new Error(`Choose bit 0–${r.ct.length * 8 - 1}.`);
    const modified = r.ct.slice(); modified[j >>> 3] ^= 1 << (j & 7);
    await showModified(r.pt, r.ct, modified, r.iv, epoch);
  });
  for (let bit = 0; bit < 8; bit++) {
    const button = document.createElement('button'); button.type = 'button'; button.className = 'btn btn-secondary';
    button.disabled = true;
    button.textContent = `Bit ${bit}`; button.setAttribute('aria-label', `Flip ciphertext bit ${bit}`);
    button.addEventListener('click', () => { el<HTMLInputElement>('bit').value = String(bit); el('flip').click(); });
    el('bits').append(button);
  }
  action('preset', async () => {
    const version = epoch, pt = textToBytes('PAY 0100'), target = textToBytes('PAY 9100'), iv = freshIV();
    const ct = await ofbXor(await getKey(), iv, pt);
    const modified = xor(ct, xor(pt, target));
    await showModified(pt, ct, modified, iv, version);
  });
}
