/**
 * gcm.ts — GCM mode with AAD, tag truncation, full decrypt + tamper demos
 */

import {
  hexEncode,
  textToBytes,
  bytesToText,
  announceError,
  aesEncrypt,
  aesDecrypt,
} from './ui';
import { gcmMath, renderMath } from './helpers';

async function generateGCMKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

async function exportKeyHex(key: CryptoKey): Promise<string> {
  const raw = await crypto.subtle.exportKey('raw', key);
  return hexEncode(new Uint8Array(raw));
}

export async function gcmEncrypt(
  key: CryptoKey,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
  tagLength: number
): Promise<{ ciphertext: Uint8Array; tag: Uint8Array; combined: Uint8Array }> {
  const combined = await aesEncrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength },
    key,
    plaintext
  );
  const buf = new Uint8Array(combined);
  const tagBytes = tagLength / 8;
  const ct = buf.slice(0, buf.length - tagBytes);
  const tag = buf.slice(buf.length - tagBytes);
  return { ciphertext: ct, tag, combined: buf };
}

export async function gcmDecrypt(
  key: CryptoKey,
  nonce: Uint8Array,
  combined: Uint8Array,
  aad: Uint8Array,
  tagLength: number
): Promise<Uint8Array> {
  const pt = await aesDecrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength },
    key,
    combined
  );
  return new Uint8Array(pt);
}

function escapeHtml(s: string): string {
  const div = document.createElement('div');
  div.textContent = s;
  return div.innerHTML;
}

export function mountGCMPanel(): void {
  const plaintextEl = document.getElementById('gcm-plaintext') as HTMLTextAreaElement;
  const aadEl = document.getElementById('gcm-aad') as HTMLInputElement;
  const tagLenEl = document.getElementById('gcm-tag-length') as HTMLSelectElement;
  const encryptBtn = document.getElementById('gcm-encrypt-btn') as HTMLButtonElement;
  const tamperBtn = document.getElementById('gcm-tamper-btn') as HTMLButtonElement;
  const keyOut = document.getElementById('gcm-key') as HTMLElement;
  const nonceOut = document.getElementById('gcm-nonce') as HTMLElement;
  const ctOut = document.getElementById('gcm-ciphertext') as HTMLElement;
  const tagOut = document.getElementById('gcm-tag') as HTMLElement;
  const tamperOutput = document.getElementById('gcm-tamper-output') as HTMLElement;
  const tamperContent = document.getElementById('gcm-tamper-content') as HTMLElement;
  const mathBox = document.getElementById('gcm-math') as HTMLElement;
  const mathRows = document.getElementById('gcm-math-rows') as HTMLElement;
  const decryptSection = document.getElementById('gcm-decrypt-section') as HTMLElement;
  const decryptCorrectBtn = document.getElementById('gcm-decrypt-correct-btn') as HTMLButtonElement;
  const decryptWrongAadBtn = document.getElementById('gcm-decrypt-wrong-aad-btn') as HTMLButtonElement;
  const decryptWrongNonceBtn = document.getElementById('gcm-decrypt-wrong-nonce-btn') as HTMLButtonElement;
  const decryptTamperBtn = document.getElementById('gcm-decrypt-tamper-btn') as HTMLButtonElement;
  const decryptOutput = document.getElementById('gcm-decrypt-output') as HTMLElement;

  let currentKey: CryptoKey | null = null;
  let currentNonce: Uint8Array | null = null;
  let currentCombined: Uint8Array | null = null;
  let currentCiphertext: Uint8Array | null = null;
  let currentTag: Uint8Array | null = null;
  let currentAAD: Uint8Array | null = null;
  let currentPlaintext: Uint8Array | null = null;
  let currentTagLength = 128;

  encryptBtn.addEventListener('click', async () => {
    try {
      currentKey = await generateGCMKey();
      currentNonce = crypto.getRandomValues(new Uint8Array(12));
      currentTagLength = parseInt(tagLenEl.value, 10);
      const keyHex = await exportKeyHex(currentKey);
      keyOut.textContent = keyHex;
      nonceOut.textContent = hexEncode(currentNonce);
      const plain = textToBytes(plaintextEl.value || 'GCM provides authenticated encryption.');
      currentPlaintext = plain;
      currentAAD = textToBytes(aadEl.value || '');
      const { ciphertext, tag, combined } = await gcmEncrypt(
        currentKey,
        currentNonce,
        plain,
        currentAAD,
        currentTagLength
      );
      currentCombined = combined;
      currentCiphertext = ciphertext;
      currentTag = tag;
      ctOut.textContent = hexEncode(ciphertext);
      tagOut.textContent = hexEncode(tag);
      if (currentTagLength < 128) {
        // Do NOT print "~2^t attempts". NIST SP 800-38D Appendix B is explicit
        // that GCM does WORSE than the generic 1/2^t bound: a targeted forgery
        // succeeds with probability approximately n/2^t, where n is the number
        // of blocks of ciphertext + AAD, and each success leaks the hash
        // subkey H, making later forgeries easier still.
        const blocks =
          Math.ceil(ciphertext.length / 16) + Math.ceil(currentAAD.length / 16);
        tagOut.textContent +=
          ` ⚠ ${currentTagLength}-bit tag: a targeted forgery succeeds with probability` +
          ` ~n/2^${currentTagLength}, n = ${blocks} block(s) of ciphertext+AAD — not 2^-${currentTagLength}`;
      }
      renderMath(mathRows, gcmMath(currentNonce, plain, ciphertext, tag));
      mathBox.hidden = false;
      tamperBtn.disabled = false;
      tamperOutput.hidden = true;
      decryptSection.hidden = false;
      decryptOutput.hidden = true;
    } catch (err) {
      announceError(`GCM encryption failed: ${(err as Error).message}`);
    }
  });

  tamperBtn.addEventListener('click', async () => {
    if (!currentKey || !currentNonce || !currentCombined || !currentAAD) return;
    try {
      const tampered = new Uint8Array(currentCombined);
      tampered[0] ^= 0x01;
      tamperOutput.hidden = false;
      try {
        await gcmDecrypt(currentKey, currentNonce, tampered, currentAAD, currentTagLength);
        tamperContent.innerHTML = `
          <p style="color:var(--danger);font-weight:700;">⚠ Unexpected: decryption succeeded despite tampering!</p>
        `;
      } catch {
        tamperContent.innerHTML = `
          <p><strong>Tampered ciphertext (flipped bit 0 of byte 0):</strong></p>
          <div class="hex-output" style="margin:0.5rem 0;">
            <span style="color:var(--danger);font-weight:700">${hexEncode(tampered.slice(0, 1))}</span>${hexEncode(tampered.slice(1))}
          </div>
          <p style="margin-top:0.5rem;font-weight:700;color:var(--success);">
            ✓ Decryption REJECTED — authentication tag verification failed!
          </p>
          <p style="font-size:0.82rem;margin-top:0.4rem;">
            GCM detected the 1-bit modification. The GHASH authentication tag over the ciphertext,
            AAD, and lengths does not match. No plaintext was released.
          </p>
          ${currentTagLength < 128 ? `
          <p style="margin-top:0.75rem;padding:0.5rem;background-color:var(--warning-bg);border:1px solid var(--warning);border-radius:4px;font-size:0.82rem;">
            <strong>Tag truncation note (NIST SP 800-38D Appendix B):</strong> a random ${currentTagLength}-bit tag
            guess is correct with probability 2<sup>−${currentTagLength}</sup>, but GCM does not hold that line.
            NIST states that "an adversary can choose tags that increase this probability, proportional to the
            total length of the ciphertext and AAD": a targeted forgery succeeds with probability approximately
            <em>n</em>/2<sup>${currentTagLength}</sup> for an <em>n</em>-block input, and every success leaks
            information about the GHASH subkey H, so later forgeries get easier. That is why SP 800-38D confines
            32- and 64-bit tags to Appendix C, with hard caps on message length and invocation count. Use 128-bit tags.
          </p>` : ''}
        `;
      }
    } catch (err) {
      announceError(`Tamper demo failed: ${(err as Error).message}`);
    }
  });

  // ─── Decrypt demos ──
  decryptCorrectBtn.addEventListener('click', async () => {
    if (!currentKey || !currentNonce || !currentCombined || !currentAAD) return;
    try {
      const pt = await gcmDecrypt(currentKey, currentNonce, currentCombined, currentAAD, currentTagLength);
      decryptOutput.hidden = false;
      decryptOutput.innerHTML = `
        <p><strong>Decrypt with correct key + nonce + AAD:</strong></p>
        <code class="decrypt-result decrypt-ok">${escapeHtml(bytesToText(pt))}</code>
        <p class="decrypt-takeaway">✓ Plaintext recovered AND authenticated. The tag matched.</p>
      `;
    } catch (e) {
      decryptOutput.hidden = false;
      decryptOutput.innerHTML = `<p class="decrypt-fail">Decrypt failed: ${escapeHtml((e as Error).message)}</p>`;
    }
  });

  decryptWrongAadBtn.addEventListener('click', async () => {
    if (!currentKey || !currentNonce || !currentCombined) return;
    try {
      const wrongAAD = textToBytes('this-was-not-the-original-AAD');
      await gcmDecrypt(currentKey, currentNonce, currentCombined, wrongAAD, currentTagLength);
      decryptOutput.hidden = false;
      decryptOutput.innerHTML = `<p style="color:var(--danger);">⚠ Unexpected: decryption succeeded with wrong AAD!</p>`;
    } catch {
      decryptOutput.hidden = false;
      decryptOutput.innerHTML = `
        <p><strong>Decrypt with WRONG AAD:</strong></p>
        <p class="decrypt-takeaway decrypt-ok">✓ REJECTED. The AAD is part of the authentication tag — change it, tag fails, no plaintext is released. This is what binds metadata to ciphertext.</p>
      `;
    }
  });

  decryptWrongNonceBtn.addEventListener('click', async () => {
    if (!currentKey || !currentCombined || !currentAAD) return;
    try {
      const wrongNonce = crypto.getRandomValues(new Uint8Array(12));
      await gcmDecrypt(currentKey, wrongNonce, currentCombined, currentAAD, currentTagLength);
      decryptOutput.hidden = false;
      decryptOutput.innerHTML = `<p style="color:var(--danger);">⚠ Unexpected: decryption succeeded with wrong nonce!</p>`;
    } catch {
      decryptOutput.hidden = false;
      decryptOutput.innerHTML = `
        <p><strong>Decrypt with WRONG nonce:</strong></p>
        <p class="decrypt-takeaway decrypt-ok">✓ REJECTED. The nonce drives both the keystream AND J₀ for the tag — wrong nonce, wrong tag.</p>
      `;
    }
  });

  decryptTamperBtn.addEventListener('click', async () => {
    if (!currentKey || !currentNonce || !currentCombined || !currentAAD) return;
    const tampered = new Uint8Array(currentCombined);
    tampered[0] ^= 0x01;
    try {
      await gcmDecrypt(currentKey, currentNonce, tampered, currentAAD, currentTagLength);
      decryptOutput.hidden = false;
      decryptOutput.innerHTML = `<p style="color:var(--danger);">⚠ Unexpected: decryption succeeded after tampering!</p>`;
    } catch {
      decryptOutput.hidden = false;
      decryptOutput.innerHTML = `
        <p><strong>Decrypt with 1-bit ciphertext flip:</strong></p>
        <p class="decrypt-takeaway decrypt-ok">✓ REJECTED. The tag covers every bit of ciphertext. Compare this with CBC/CTR, where the same flip would silently return mangled plaintext.</p>
      `;
    }
  });
}
