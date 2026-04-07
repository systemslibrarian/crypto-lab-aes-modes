/**
 * cbc.ts — CBC mode implementation with IV reuse and bit-flip demos
 *
 * Uses WebCrypto AES-CBC (AES-256). Demonstrates:
 * - Block chaining visualization
 * - IV reuse vulnerability
 * - Bit-flip attack on ciphertext
 */

import { hexEncode, hexDecode, textToBytes, bytesToText, announceError, aesEncrypt, aesDecrypt } from './ui';

export interface CBCResult {
  key: CryptoKey;
  iv: Uint8Array;
  ciphertext: Uint8Array;
  keyHex: string;
  ivHex: string;
  ciphertextHex: string;
}

async function generateCBCKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: 'AES-CBC', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

async function exportKeyHex(key: CryptoKey): Promise<string> {
  const raw = await crypto.subtle.exportKey('raw', key);
  return hexEncode(new Uint8Array(raw));
}

export async function cbcEncrypt(
  key: CryptoKey,
  iv: Uint8Array,
  plaintext: Uint8Array
): Promise<Uint8Array> {
  const ct = await aesEncrypt(
    { name: 'AES-CBC', iv },
    key,
    plaintext
  );
  return new Uint8Array(ct);
}

export async function cbcDecrypt(
  key: CryptoKey,
  iv: Uint8Array,
  ciphertext: Uint8Array
): Promise<Uint8Array> {
  const pt = await aesDecrypt(
    { name: 'AES-CBC', iv },
    key,
    ciphertext
  );
  return new Uint8Array(pt);
}

function renderChainViz(container: HTMLElement, ciphertext: Uint8Array, iv: Uint8Array): void {
  container.innerHTML = '';
  const BLOCK = 16;

  // IV block
  const ivEl = document.createElement('div');
  ivEl.className = 'chain-block';
  ivEl.textContent = 'IV';
  ivEl.title = hexEncode(iv);
  ivEl.setAttribute('aria-label', `IV: ${hexEncode(iv).slice(0, 16)}…`);
  container.appendChild(ivEl);

  const numBlocks = Math.ceil(ciphertext.length / BLOCK);
  for (let i = 0; i < numBlocks; i++) {
    // Arrow
    const arrow = document.createElement('span');
    arrow.className = 'chain-arrow';
    arrow.textContent = '→';
    arrow.setAttribute('aria-hidden', 'true');
    container.appendChild(arrow);

    // Block
    const blockEl = document.createElement('div');
    blockEl.className = 'chain-block';
    const blockHex = hexEncode(ciphertext.slice(i * BLOCK, (i + 1) * BLOCK));
    blockEl.textContent = `C${i}`;
    blockEl.title = blockHex;
    blockEl.setAttribute('aria-label', `Ciphertext block ${i}: ${blockHex.slice(0, 16)}…`);
    container.appendChild(blockEl);
  }
}

export function mountCBCPanel(): void {
  const plaintextEl = document.getElementById('cbc-plaintext') as HTMLTextAreaElement;
  const ivInput = document.getElementById('cbc-iv') as HTMLInputElement;
  const encryptBtn = document.getElementById('cbc-encrypt-btn') as HTMLButtonElement;
  const ivReuseBtn = document.getElementById('cbc-iv-reuse-btn') as HTMLButtonElement;
  const bitflipBtn = document.getElementById('cbc-bitflip-btn') as HTMLButtonElement;
  const keyOut = document.getElementById('cbc-key') as HTMLElement;
  const ivOut = document.getElementById('cbc-iv-output') as HTMLElement;
  const ctOut = document.getElementById('cbc-ciphertext') as HTMLElement;
  const chainBlocks = document.getElementById('cbc-chain-blocks') as HTMLElement;
  const vulnOutput = document.getElementById('cbc-vuln-output') as HTMLElement;
  const vulnContent = document.getElementById('cbc-vuln-content') as HTMLElement;

  let lastResult: CBCResult | null = null;

  encryptBtn.addEventListener('click', async () => {
    try {
      const key = await generateCBCKey();
      const keyHex = await exportKeyHex(key);

      let iv: Uint8Array;
      const ivText = ivInput.value.trim();
      if (ivText.length === 32 && /^[0-9a-fA-F]+$/.test(ivText)) {
        iv = hexDecode(ivText);
      } else {
        iv = crypto.getRandomValues(new Uint8Array(16));
      }

      const plaintext = textToBytes(plaintextEl.value || 'Hello, AES-CBC!');
      const ciphertext = await cbcEncrypt(key, iv, plaintext);

      const ivHex = hexEncode(iv);
      const ciphertextHex = hexEncode(ciphertext);

      keyOut.textContent = keyHex;
      ivOut.textContent = ivHex;
      ctOut.textContent = ciphertextHex;

      renderChainViz(chainBlocks, ciphertext, iv);

      lastResult = { key, iv, ciphertext, keyHex, ivHex, ciphertextHex };
      ivReuseBtn.disabled = false;
      bitflipBtn.disabled = false;
      vulnOutput.hidden = true;
    } catch (err) {
      announceError(`CBC encryption failed: ${(err as Error).message}`);
    }
  });

  // IV Reuse demo
  ivReuseBtn.addEventListener('click', async () => {
    if (!lastResult) return;
    try {
      const { key, iv } = lastResult;
      const plaintext = textToBytes(plaintextEl.value || 'Hello, AES-CBC!');

      // Encrypt same plaintext with same IV
      const ct2 = await cbcEncrypt(key, iv, plaintext);
      const ct2Hex = hexEncode(ct2);

      vulnOutput.hidden = false;
      const match = ct2Hex === lastResult.ciphertextHex;
      vulnContent.innerHTML = `
        <p><strong>Same plaintext + same IV + same key:</strong></p>
        <div class="hex-output" style="margin:0.5rem 0;">${lastResult.ciphertextHex}</div>
        <div class="hex-output" style="margin:0.5rem 0;">${ct2Hex}</div>
        <p style="margin-top:0.5rem;font-weight:700;color:${match ? 'var(--danger)' : 'var(--success)'}">
          ${match
            ? '⚠ IDENTICAL ciphertexts! IV reuse leaks that the same message was sent.'
            : '✓ Different ciphertexts (different plaintext or key).'}
        </p>
        <p style="font-size:0.82rem;color:var(--text-muted);margin-top:0.4rem;">
          ${match ? 'Text equivalent: VULNERABILITY — identical ciphertext detected' : 'Text equivalent: Safe — ciphertexts differ'}
        </p>
      `;
    } catch (err) {
      announceError(`IV reuse demo failed: ${(err as Error).message}`);
    }
  });

  // Bit-flip demo
  bitflipBtn.addEventListener('click', async () => {
    if (!lastResult) return;
    try {
      const { key, iv, ciphertext } = lastResult;

      // Decrypt original
      const origPlain = await cbcDecrypt(key, iv, ciphertext);
      const origText = bytesToText(origPlain);

      // Flip bit 0 of first ciphertext byte (affects second plaintext block in CBC,
      // or if < 2 blocks, corrupts block 1 via IV-like effect)
      const tampered = new Uint8Array(ciphertext);
      // For single-block: flip a bit in the IV to show controlled corruption
      // For multi-block: flip bit in block 0 to corrupt block 1
      const flipIdx = 0;
      tampered[flipIdx] ^= 0x01; // flip least significant bit

      let decryptedText: string;
      try {
        const decrypted = await cbcDecrypt(key, iv, tampered);
        decryptedText = bytesToText(decrypted);
      } catch {
        // Padding may be invalid — that's expected!
        decryptedText = '(decryption failed — padding became invalid after bit flip)';
      }

      vulnOutput.hidden = false;
      vulnContent.innerHTML = `
        <p><strong>Bit-flip attack:</strong> Flipped bit 0 of ciphertext byte 0</p>
        <p style="margin-top:0.5rem;">Original plaintext: <code>${escapeHtml(origText)}</code></p>
        <p>After bit flip: <code>${escapeHtml(decryptedText)}</code></p>
        <p style="margin-top:0.5rem;font-size:0.82rem;">
          <strong>Ciphertext (original):</strong>
        </p>
        <div class="hex-output" style="margin:0.3rem 0;">${hexEncode(ciphertext)}</div>
        <p style="font-size:0.82rem;"><strong>Ciphertext (tampered):</strong></p>
        <div class="hex-output" style="margin:0.3rem 0;">
          <span style="color:var(--danger);font-weight:700">${hexEncode(tampered.slice(0, 1))}</span>${hexEncode(tampered.slice(1))}
        </div>
        <p style="margin-top:0.5rem;font-weight:700;color:var(--danger)">
          ⚠ Controlled plaintext corruption without knowing the key!
        </p>
        <p style="font-size:0.82rem;color:var(--text-muted);margin-top:0.3rem;">
          Text equivalent: VULNERABILITY — ciphertext bit flip causes controlled plaintext modification
        </p>
      `;
    } catch (err) {
      announceError(`Bit-flip demo failed: ${(err as Error).message}`);
    }
  });
}

function escapeHtml(s: string): string {
  const div = document.createElement('div');
  div.textContent = s;
  return div.innerHTML;
}
