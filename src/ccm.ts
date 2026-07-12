/**
 * ccm.ts — CCM mode (RFC 3610 / NIST SP 800-38C) with full encrypt + decrypt + tamper demo.
 * Built from @noble/ciphers single-block AES (ECB disablePadding).
 *
 * Correctness is pinned by unit tests: src/ccm.test.ts checks this
 * implementation against the four RFC 3610 known-answer vectors and against
 * @noble/ciphers' independent CCM. The AAD length prefix follows the full
 * RFC 3610 §2.2 encoding (2-byte, 6-byte 0xFFFE, and 10-byte 0xFFFF forms),
 * not only the <2^16 case.
 */

import { ecb } from '@noble/ciphers/aes';
import { hexEncode, textToBytes, bytesToText, announceError } from './ui';
import { ccmMath, renderMath } from './helpers';

const BLOCK = 16;

export function aesBlock(key: Uint8Array, block: Uint8Array): Uint8Array {
  const cipher = ecb(key, { disablePadding: true });
  return cipher.encrypt(block);
}

function xorBlocks(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(BLOCK);
  for (let i = 0; i < BLOCK; i++) out[i] = a[i] ^ (b[i] ?? 0);
  return out;
}

function ctEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function formatB0(
  nonce: Uint8Array,
  plaintextLen: number,
  aadLen: number,
  tagLen: number
): Uint8Array {
  const q = 15 - nonce.length;
  const flags = (aadLen > 0 ? 0x40 : 0) | (((tagLen - 2) / 2) << 3) | (q - 1);
  const b0 = new Uint8Array(BLOCK);
  b0[0] = flags;
  b0.set(nonce, 1);
  let len = plaintextLen;
  for (let i = BLOCK - 1; i >= BLOCK - q; i--) {
    b0[i] = len & 0xff;
    len >>>= 8;
  }
  return b0;
}

/**
 * Encode the length prefix for the associated data per RFC 3610 §2.2 /
 * NIST SP 800-38C A.2.2. The prefix width depends on the AAD length `a`:
 *   0 < a < 2^16 - 2^8   → 2 bytes, big-endian
 *   2^16 - 2^8 <= a < 2^32 → 0xFF 0xFE, then 4 bytes big-endian
 *   2^32 <= a < 2^64       → 0xFF 0xFF, then 8 bytes big-endian
 * (JavaScript numbers are used for the demo's practical range; the 2^64 arm
 * is expressed for completeness but AAD that large is not representable here.)
 */
export function encodeAADLength(aadLen: number): Uint8Array {
  if (aadLen < 0xff00) {
    return Uint8Array.of((aadLen >>> 8) & 0xff, aadLen & 0xff);
  }
  if (aadLen < 0x1_0000_0000) {
    return Uint8Array.of(
      0xff,
      0xfe,
      (aadLen >>> 24) & 0xff,
      (aadLen >>> 16) & 0xff,
      (aadLen >>> 8) & 0xff,
      aadLen & 0xff,
    );
  }
  // 2^32 <= a < 2^64: 0xFF 0xFF followed by an 8-byte big-endian length.
  const out = new Uint8Array(10);
  out[0] = 0xff;
  out[1] = 0xff;
  let len = aadLen;
  for (let i = 9; i >= 2; i--) {
    out[i] = len % 256;
    len = Math.floor(len / 256);
  }
  return out;
}

export function formatAAD(aad: Uint8Array): Uint8Array {
  if (aad.length === 0) return new Uint8Array(0);
  const prefix = encodeAADLength(aad.length);
  const encoded = new Uint8Array(prefix.length + aad.length);
  encoded.set(prefix);
  encoded.set(aad, prefix.length);
  const padded = new Uint8Array(Math.ceil(encoded.length / BLOCK) * BLOCK);
  padded.set(encoded);
  return padded;
}

export function formatCtrBlock(nonce: Uint8Array, counter: number): Uint8Array {
  const q = 15 - nonce.length;
  const a = new Uint8Array(BLOCK);
  a[0] = q - 1;
  a.set(nonce, 1);
  let c = counter;
  for (let i = BLOCK - 1; i >= BLOCK - q; i--) {
    a[i] = c & 0xff;
    c >>>= 8;
  }
  return a;
}

export function computeMac(
  key: Uint8Array,
  nonce: Uint8Array,
  data: Uint8Array,
  aad: Uint8Array,
  tagLen: number
): Uint8Array {
  const b0 = formatB0(nonce, data.length, aad.length, tagLen);
  let mac = aesBlock(key, b0);
  const aadBlocks = formatAAD(aad);
  for (let i = 0; i < aadBlocks.length; i += BLOCK) {
    mac = aesBlock(key, xorBlocks(mac, aadBlocks.slice(i, i + BLOCK)));
  }
  for (let i = 0; i < data.length; i += BLOCK) {
    const block = new Uint8Array(BLOCK);
    block.set(data.slice(i, Math.min(i + BLOCK, data.length)));
    mac = aesBlock(key, xorBlocks(mac, block));
  }
  return mac.slice(0, tagLen);
}

function ctrXor(
  key: Uint8Array,
  nonce: Uint8Array,
  data: Uint8Array
): Uint8Array {
  const out = new Uint8Array(data.length);
  const numBlocks = Math.ceil(data.length / BLOCK);
  for (let i = 0; i < numBlocks; i++) {
    const Si = aesBlock(key, formatCtrBlock(nonce, i + 1));
    const offset = i * BLOCK;
    const end = Math.min(offset + BLOCK, data.length);
    for (let j = offset; j < end; j++) {
      out[j] = data[j] ^ Si[j - offset];
    }
  }
  return out;
}

export function ccmEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
  tagLen: number = 16
): Uint8Array {
  const T = computeMac(key, nonce, plaintext, aad, tagLen);
  const S0 = aesBlock(key, formatCtrBlock(nonce, 0));
  const encTag = new Uint8Array(tagLen);
  for (let i = 0; i < tagLen; i++) encTag[i] = T[i] ^ S0[i];
  const ciphertext = ctrXor(key, nonce, plaintext);
  const out = new Uint8Array(ciphertext.length + tagLen);
  out.set(ciphertext);
  out.set(encTag, ciphertext.length);
  return out;
}

export function ccmDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  combined: Uint8Array,
  aad: Uint8Array,
  tagLen: number = 16
): Uint8Array {
  if (combined.length < tagLen) throw new Error('CCM input too short');
  const ciphertext = combined.slice(0, combined.length - tagLen);
  const encTag = combined.slice(combined.length - tagLen);
  const S0 = aesBlock(key, formatCtrBlock(nonce, 0));
  const T = new Uint8Array(tagLen);
  for (let i = 0; i < tagLen; i++) T[i] = encTag[i] ^ S0[i];
  const plaintext = ctrXor(key, nonce, ciphertext);
  const expectedT = computeMac(key, nonce, plaintext, aad, tagLen);
  if (!ctEqual(T, expectedT)) throw new Error('CCM authentication failed');
  return plaintext;
}

function escapeHtml(s: string): string {
  const div = document.createElement('div');
  div.textContent = s;
  return div.innerHTML;
}

export function mountCCMPanel(): void {
  const plaintextEl = document.getElementById('ccm-plaintext') as HTMLTextAreaElement;
  const aadEl = document.getElementById('ccm-aad') as HTMLInputElement;
  const encryptBtn = document.getElementById('ccm-encrypt-btn') as HTMLButtonElement;
  const tamperBtn = document.getElementById('ccm-tamper-btn') as HTMLButtonElement;
  const keyOut = document.getElementById('ccm-key') as HTMLElement;
  const nonceOut = document.getElementById('ccm-nonce') as HTMLElement;
  const ctOut = document.getElementById('ccm-ciphertext') as HTMLElement;
  const mathBox = document.getElementById('ccm-math') as HTMLElement;
  const mathRows = document.getElementById('ccm-math-rows') as HTMLElement;
  const tamperOutput = document.getElementById('ccm-tamper-output') as HTMLElement;
  const tamperContent = document.getElementById('ccm-tamper-content') as HTMLElement;
  const decryptSection = document.getElementById('ccm-decrypt-section') as HTMLElement;
  const decryptCorrectBtn = document.getElementById('ccm-decrypt-correct-btn') as HTMLButtonElement;
  const decryptTamperBtn = document.getElementById('ccm-decrypt-tamper-btn') as HTMLButtonElement;
  const decryptOutput = document.getElementById('ccm-decrypt-output') as HTMLElement;

  let currentKey: Uint8Array | null = null;
  let currentNonce: Uint8Array | null = null;
  let currentAAD: Uint8Array | null = null;
  let currentPlaintext: Uint8Array | null = null;
  let currentCombined: Uint8Array | null = null;

  encryptBtn.addEventListener('click', () => {
    try {
      const key = crypto.getRandomValues(new Uint8Array(16));
      const nonce = crypto.getRandomValues(new Uint8Array(13));
      const plaintext = textToBytes(plaintextEl.value || 'CCM for constrained environments.');
      const aad = textToBytes(aadEl.value || '');
      const combined = ccmEncrypt(key, nonce, plaintext, aad, 16);
      const ciphertextOnly = combined.slice(0, combined.length - 16);

      currentKey = key;
      currentNonce = nonce;
      currentAAD = aad;
      currentPlaintext = plaintext;
      currentCombined = combined;

      keyOut.textContent = hexEncode(key);
      nonceOut.textContent = hexEncode(nonce);
      ctOut.textContent = hexEncode(combined);

      renderMath(mathRows, ccmMath(nonce, plaintext, ciphertextOnly, 16));
      mathBox.hidden = false;

      tamperBtn.disabled = false;
      tamperOutput.hidden = true;
      decryptSection.hidden = false;
      decryptOutput.hidden = true;
    } catch (err) {
      announceError(`CCM encryption failed: ${(err as Error).message}`);
    }
  });

  tamperBtn.addEventListener('click', () => {
    if (!currentKey || !currentNonce || !currentCombined || !currentAAD) return;
    const tampered = new Uint8Array(currentCombined);
    tampered[0] ^= 0x01;
    tamperOutput.hidden = false;
    try {
      ccmDecrypt(currentKey, currentNonce, tampered, currentAAD, 16);
      tamperContent.innerHTML = `<p style="color:var(--danger);">⚠ Unexpected: tampered ciphertext was accepted!</p>`;
    } catch {
      tamperContent.innerHTML = `
        <p><strong>Tampered ciphertext (flipped bit 0 of byte 0):</strong></p>
        <div class="hex-output" style="margin:0.5rem 0;">
          <span style="color:var(--danger);font-weight:700">${hexEncode(tampered.slice(0, 1))}</span>${hexEncode(tampered.slice(1))}
        </div>
        <p style="margin-top:0.5rem;font-weight:700;color:var(--success);">
          ✓ Decryption REJECTED — CBC-MAC tag verification failed.
        </p>
        <p style="font-size:0.82rem;margin-top:0.4rem;">
          CCM recomputed the CBC-MAC over the (mangled) decrypted plaintext + AAD and compared with the
          decrypted tag. They no longer match, so no plaintext is released.
        </p>
      `;
    }
  });

  // ─── Decrypt demos ──
  decryptCorrectBtn.addEventListener('click', () => {
    if (!currentKey || !currentNonce || !currentCombined || !currentAAD) return;
    try {
      const pt = ccmDecrypt(currentKey, currentNonce, currentCombined, currentAAD, 16);
      decryptOutput.hidden = false;
      decryptOutput.innerHTML = `
        <p><strong>Decrypt with correct key + nonce + AAD:</strong></p>
        <code class="decrypt-result decrypt-ok">${escapeHtml(bytesToText(pt))}</code>
        <p class="decrypt-takeaway">✓ Authenticated AND decrypted. CBC-MAC verified before plaintext was released.</p>
      `;
    } catch (e) {
      decryptOutput.hidden = false;
      decryptOutput.innerHTML = `<p class="decrypt-fail">Decrypt failed: ${escapeHtml((e as Error).message)}</p>`;
    }
  });

  decryptTamperBtn.addEventListener('click', () => {
    if (!currentKey || !currentNonce || !currentCombined || !currentAAD) return;
    const tampered = new Uint8Array(currentCombined);
    tampered[0] ^= 0x01;
    try {
      ccmDecrypt(currentKey, currentNonce, tampered, currentAAD, 16);
      decryptOutput.hidden = false;
      decryptOutput.innerHTML = `<p style="color:var(--danger);">⚠ Unexpected: tampered ciphertext accepted!</p>`;
    } catch {
      decryptOutput.hidden = false;
      decryptOutput.innerHTML = `
        <p><strong>Decrypt with 1-bit ciphertext flip:</strong></p>
        <p class="decrypt-takeaway decrypt-ok">✓ REJECTED. Same as GCM — AEAD wins. This is what Zigbee/BLE rely on at the link layer.</p>
      `;
    }
  });
}
