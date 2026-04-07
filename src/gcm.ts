/**
 * gcm.ts — GCM mode with AAD and tag truncation demos
 *
 * Uses WebCrypto AES-GCM (AES-256). Demonstrates:
 * - Authenticated encryption with AAD
 * - Tag truncation weakness (NIST SP 800-38D §5.2.1.2)
 * - Tamper detection (ciphertext modification → decryption failure)
 */

import { hexEncode, textToBytes, announceError, aesEncrypt, aesDecrypt } from './ui';

async function generateGCMKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
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
    {
      name: 'AES-GCM',
      iv: nonce,
      additionalData: aad,
      tagLength,
    },
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
    {
      name: 'AES-GCM',
      iv: nonce,
      additionalData: aad,
      tagLength,
    },
    key,
    combined
  );
  return new Uint8Array(pt);
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

  let currentKey: CryptoKey | null = null;
  let currentNonce: Uint8Array | null = null;
  let currentCombined: Uint8Array | null = null;
  let currentAAD: Uint8Array | null = null;
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
      currentAAD = textToBytes(aadEl.value || '');

      const { ciphertext, tag, combined } = await gcmEncrypt(
        currentKey,
        currentNonce,
        plain,
        currentAAD,
        currentTagLength
      );

      currentCombined = combined;
      ctOut.textContent = hexEncode(ciphertext);
      tagOut.textContent = hexEncode(tag);

      tamperBtn.disabled = false;
      tamperOutput.hidden = true;

      // Show tag truncation warning if not 128
      if (currentTagLength < 128) {
        const forgeryBits = currentTagLength;
        tagOut.textContent += ` ⚠ ${forgeryBits}-bit tag: ~2^${forgeryBits} attempts for forgery`;
      }
    } catch (err) {
      announceError(`GCM encryption failed: ${(err as Error).message}`);
    }
  });

  tamperBtn.addEventListener('click', async () => {
    if (!currentKey || !currentNonce || !currentCombined || !currentAAD) return;

    try {
      // Tamper with ciphertext: flip one bit
      const tampered = new Uint8Array(currentCombined);
      tampered[0] ^= 0x01;

      tamperOutput.hidden = false;

      try {
        await gcmDecrypt(currentKey, currentNonce, tampered, currentAAD, currentTagLength);
        // Should NOT reach here
        tamperContent.innerHTML = `
          <p style="color:var(--danger);font-weight:700;">
            ⚠ Unexpected: decryption succeeded despite tampering!
          </p>
        `;
      } catch {
        // Expected! Authentication tag verification failed
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
          <p style="font-size:0.82rem;color:var(--text-muted);margin-top:0.3rem;">
            Text equivalent: SECURE — tampered ciphertext correctly rejected by GCM authentication
          </p>
          ${currentTagLength < 128 ? `
          <p style="margin-top:0.75rem;padding:0.5rem;background:var(--warning-bg);border:1px solid var(--warning);border-radius:4px;font-size:0.82rem;">
            <strong>Tag truncation note (NIST SP 800-38D §5.2.1.2):</strong> With a ${currentTagLength}-bit tag,
            forgery probability per attempt is ≤ 2<sup>−${currentTagLength}</sup>. For maximum security, use 128-bit tags.
          </p>
          ` : ''}
        `;
      }
    } catch (err) {
      announceError(`Tamper demo failed: ${(err as Error).message}`);
    }
  });
}
