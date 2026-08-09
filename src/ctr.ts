/**
 * ctr.ts — CTR mode with nonce reuse demo, decrypt variants, math overlay
 */

import {
  hexEncode,
  textToBytes,
  bytesToText,
  announceError,
  aesEncrypt,
  aesDecrypt,
} from './ui';
import { ctrMath, renderMath } from './helpers';

async function generateCTRKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'AES-CTR', length: 256 }, true, ['encrypt', 'decrypt']);
}

async function exportKeyHex(key: CryptoKey): Promise<string> {
  const raw = await crypto.subtle.exportKey('raw', key);
  return hexEncode(new Uint8Array(raw));
}

function makeCounter(nonce: Uint8Array): Uint8Array {
  const counter = new Uint8Array(16);
  counter.set(nonce.slice(0, 12));
  counter[15] = 1;
  return counter;
}

export async function ctrEncrypt(
  key: CryptoKey,
  counter: Uint8Array,
  plaintext: Uint8Array
): Promise<Uint8Array> {
  const ct = await aesEncrypt({ name: 'AES-CTR', counter, length: 32 }, key, plaintext);
  return new Uint8Array(ct);
}

export async function ctrDecrypt(
  key: CryptoKey,
  counter: Uint8Array,
  ciphertext: Uint8Array
): Promise<Uint8Array> {
  const pt = await aesDecrypt({ name: 'AES-CTR', counter, length: 32 }, key, ciphertext);
  return new Uint8Array(pt);
}

function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const len = Math.min(a.length, b.length);
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = a[i] ^ b[i];
  return out;
}

function renderStreamViz(container: HTMLElement, nonce: Uint8Array, ciphertext: Uint8Array): void {
  container.innerHTML = '';
  const BLOCK = 16;
  const numBlocks = Math.ceil(ciphertext.length / BLOCK);
  for (let i = 0; i < Math.min(numBlocks, 4); i++) {
    const row = document.createElement('div');
    row.className = 'stream-row';
    const label = document.createElement('span');
    label.className = 'stream-label';
    label.textContent = `CTR[${i}]:`;
    row.appendChild(label);
    const nonceCell = document.createElement('span');
    nonceCell.className = 'stream-cell';
    nonceCell.textContent = hexEncode(nonce).slice(0, 12) + '…';
    nonceCell.title = 'Nonce (12 bytes)';
    row.appendChild(nonceCell);
    const plus = document.createElement('span');
    plus.textContent = '|';
    plus.setAttribute('aria-hidden', 'true');
    row.appendChild(plus);
    const ctrCell = document.createElement('span');
    ctrCell.className = 'stream-cell';
    ctrCell.textContent = (i + 1).toString().padStart(8, '0');
    ctrCell.title = `Counter value: ${i + 1}`;
    row.appendChild(ctrCell);
    const arrow = document.createElement('span');
    arrow.textContent = ' → AES → ⊕ P → ';
    arrow.style.fontSize = '0.72rem';
    arrow.style.color = 'var(--text-muted)';
    row.appendChild(arrow);
    const ctCell = document.createElement('span');
    ctCell.className = 'stream-cell';
    const blockHex = hexEncode(ciphertext.slice(i * BLOCK, (i + 1) * BLOCK));
    ctCell.textContent = blockHex.slice(0, 16) + (blockHex.length > 16 ? '…' : '');
    ctCell.title = `Ciphertext block ${i}: ${blockHex}`;
    row.appendChild(ctCell);
    container.appendChild(row);
  }
  if (numBlocks > 4) {
    const more = document.createElement('div');
    more.className = 'stream-row';
    more.textContent = `… and ${numBlocks - 4} more blocks`;
    more.style.color = 'var(--text-muted)';
    container.appendChild(more);
  }
}

function escapeHtml(s: string): string {
  const div = document.createElement('div');
  div.textContent = s;
  return div.innerHTML;
}

export function mountCTRPanel(): void {
  const pt1El = document.getElementById('ctr-plaintext') as HTMLTextAreaElement;
  const pt2El = document.getElementById('ctr-plaintext2') as HTMLTextAreaElement;
  const encryptBtn = document.getElementById('ctr-encrypt-btn') as HTMLButtonElement;
  const nonceReuseBtn = document.getElementById('ctr-nonce-reuse-btn') as HTMLButtonElement;
  const keyOut = document.getElementById('ctr-key') as HTMLElement;
  const counterOut = document.getElementById('ctr-counter') as HTMLElement;
  const ctOut = document.getElementById('ctr-ciphertext') as HTMLElement;
  const streamBlocks = document.getElementById('ctr-stream-blocks') as HTMLElement;
  const nonceOutput = document.getElementById('ctr-nonce-output') as HTMLElement;
  const nonceContent = document.getElementById('ctr-nonce-content') as HTMLElement;
  const mathBox = document.getElementById('ctr-math') as HTMLElement;
  const mathRows = document.getElementById('ctr-math-rows') as HTMLElement;
  const decryptSection = document.getElementById('ctr-decrypt-section') as HTMLElement;
  const decryptCorrectBtn = document.getElementById('ctr-decrypt-correct-btn') as HTMLButtonElement;
  const decryptWrongNonceBtn = document.getElementById('ctr-decrypt-wrong-nonce-btn') as HTMLButtonElement;
  const decryptTamperBtn = document.getElementById('ctr-decrypt-tamper-btn') as HTMLButtonElement;
  const decryptOutput = document.getElementById('ctr-decrypt-output') as HTMLElement;

  let currentKey: CryptoKey | null = null;
  let currentNonce: Uint8Array | null = null;
  let currentCounter: Uint8Array | null = null;
  let currentPlaintext: Uint8Array | null = null;
  let currentCiphertext: Uint8Array | null = null;

  encryptBtn.addEventListener('click', async () => {
    try {
      currentKey = await generateCTRKey();
      currentNonce = crypto.getRandomValues(new Uint8Array(12));
      currentCounter = makeCounter(currentNonce);
      const keyHex = await exportKeyHex(currentKey);
      keyOut.textContent = keyHex;
      counterOut.textContent = hexEncode(currentCounter);
      const plain = textToBytes(pt1El.value || 'AES-CTR encrypts by XORing with a keystream.');
      currentPlaintext = plain;
      const ct = await ctrEncrypt(currentKey, currentCounter, plain);
      currentCiphertext = ct;
      ctOut.textContent = hexEncode(ct);
      renderStreamViz(streamBlocks, currentNonce, ct);
      renderMath(mathRows, ctrMath(currentNonce, plain, ct));
      mathBox.hidden = false;
      nonceReuseBtn.disabled = false;
      nonceOutput.hidden = true;
      decryptSection.hidden = false;
      decryptOutput.hidden = true;
    } catch (err) {
      announceError(`CTR encryption failed: ${(err as Error).message}`);
    }
  });

  nonceReuseBtn.addEventListener('click', async () => {
    if (!currentKey || !currentCounter) return;
    try {
      const p1 = textToBytes(pt1El.value || 'AES-CTR encrypts by XORing with a keystream.');
      const p2 = textToBytes(pt2El.value || 'This is a different secret message!');
      const c1 = await ctrEncrypt(currentKey, currentCounter, p1);
      const c2 = await ctrEncrypt(currentKey, currentCounter, p2);
      const xored = xorBytes(c1, c2);
      const recoveredP2 = xorBytes(xored, p1);
      const recoveredText = bytesToText(recoveredP2.slice(0, p2.length));
      // The keystream only cancels where the two messages overlap. If P2 is the
      // longer message, its tail is NOT recovered, and the banner must not
      // claim otherwise. recoveredP2.length is min(|P1|, |P2|) by construction.
      const recoveredBytes = Math.min(recoveredP2.length, p2.length);
      const fullyRecovered = recoveredBytes === p2.length;
      const verdictLine = fullyRecovered
        ? `⚠ All ${recoveredBytes} bytes of P₂ recovered. Nonce reuse destroys CTR security.`
        : `⚠ ${recoveredBytes} of ${p2.length} bytes of P₂ recovered — the keystream only cancels where the two ` +
          `messages overlap, and P₁ is the shorter one. Make P₁ at least as long as P₂ to recover all of it. ` +
          `Nonce reuse destroys CTR security.`;
      nonceOutput.hidden = false;
      nonceContent.innerHTML = `
        <p><strong>Both messages encrypted with the same nonce:</strong></p>
        <p style="font-size:0.82rem;">C₁ = Enc(key, nonce, P₁)</p>
        <p style="font-size:0.82rem;">C₂ = Enc(key, nonce, P₂)</p>
        <p style="font-size:0.82rem;margin-top:0.4rem;"><strong>C₁ ⊕ C₂ = P₁ ⊕ P₂</strong> (keystream cancels!)</p>
        <div style="margin:0.5rem 0;">
          <p style="font-size:0.78rem;color:var(--text-muted);">C₁ ⊕ C₂ (hex):</p>
          <div class="hex-output" tabindex="0" role="group" aria-label="C1 XOR C2, hexadecimal">${hexEncode(xored)}</div>
        </div>
        <p style="margin-top:0.5rem;"><strong>If attacker knows P₁, they recover P₂:</strong></p>
        <p style="font-size:0.82rem;">(P₁ ⊕ P₂) ⊕ P₁ = P₂</p>
        <div class="hex-output" style="margin-top:0.3rem;font-weight:700;color:var(--danger);" tabindex="0" role="group" aria-label="Recovered second plaintext">
          ${escapeHtml(recoveredText)}
        </div>
        <p style="margin-top:0.5rem;font-weight:700;color:var(--danger);">
          ${escapeHtml(verdictLine)}
        </p>
      `;
    } catch (err) {
      announceError(`Nonce reuse demo failed: ${(err as Error).message}`);
    }
  });

  // ─── Decrypt demos ──
  decryptCorrectBtn.addEventListener('click', async () => {
    if (!currentKey || !currentCounter || !currentCiphertext) return;
    try {
      const pt = await ctrDecrypt(currentKey, currentCounter, currentCiphertext);
      decryptOutput.hidden = false;
      decryptOutput.innerHTML = `
        <p><strong>Decrypt with correct key + counter:</strong></p>
        <code class="decrypt-result decrypt-ok">${escapeHtml(bytesToText(pt))}</code>
        <p class="decrypt-takeaway">✓ Plaintext recovered. CTR decrypt is just encrypt re-run — same keystream, XOR cancels out.</p>
      `;
    } catch (e) {
      decryptOutput.hidden = false;
      decryptOutput.innerHTML = `<p class="decrypt-fail">Decrypt failed: ${escapeHtml((e as Error).message)}</p>`;
    }
  });

  decryptWrongNonceBtn.addEventListener('click', async () => {
    if (!currentKey || !currentCiphertext) return;
    try {
      const wrongCounter = crypto.getRandomValues(new Uint8Array(16));
      const pt = await ctrDecrypt(currentKey, wrongCounter, currentCiphertext);
      decryptOutput.hidden = false;
      decryptOutput.innerHTML = `
        <p><strong>Decrypt with WRONG nonce/counter:</strong></p>
        <code class="decrypt-result decrypt-bad">${escapeHtml(bytesToText(pt))}</code>
        <p class="decrypt-takeaway">⚠ Pure garbage — and no error. CTR has no integrity check; the keystream is just different, so XOR returns random-looking bytes.</p>
      `;
    } catch (e) {
      decryptOutput.hidden = false;
      decryptOutput.innerHTML = `<p class="decrypt-fail">Decrypt failed: ${escapeHtml((e as Error).message)}</p>`;
    }
  });

  decryptTamperBtn.addEventListener('click', async () => {
    if (!currentKey || !currentCounter || !currentCiphertext) return;
    try {
      const tampered = new Uint8Array(currentCiphertext);
      tampered[0] ^= 0x01;
      const pt = await ctrDecrypt(currentKey, currentCounter, tampered);
      decryptOutput.hidden = false;
      decryptOutput.innerHTML = `
        <p><strong>Decrypt with 1-bit ciphertext flip:</strong></p>
        <code class="decrypt-result decrypt-bad">${escapeHtml(bytesToText(pt))}</code>
        <p class="decrypt-takeaway">⚠ CTR bit-flips translate 1:1 to plaintext bit-flips. The first byte changed in a fully controlled way, with no error. GCM/CCM would have rejected this.</p>
      `;
    } catch (e) {
      decryptOutput.hidden = false;
      decryptOutput.innerHTML = `<p class="decrypt-fail">Decrypt failed: ${escapeHtml((e as Error).message)}</p>`;
    }
  });
}
