/**
 * cbc.ts — CBC mode with IV reuse, bit-flip, targeted bit-flip, and full decrypt demo
 */

import {
  hexEncode,
  hexDecode,
  textToBytes,
  bytesToText,
  pkcs7Pad,
  announceError,
  aesEncrypt,
  aesDecrypt,
} from './ui';
import { cbcMath, renderMath } from './helpers';

const BLOCK_SIZE = 16;

export interface CBCResult {
  key: CryptoKey;
  iv: Uint8Array;
  paddedPlaintext: Uint8Array;
  ciphertext: Uint8Array;
  keyHex: string;
  ivHex: string;
  ciphertextHex: string;
}

async function generateCBCKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'AES-CBC', length: 256 }, true, ['encrypt', 'decrypt']);
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
  const ct = await aesEncrypt({ name: 'AES-CBC', iv }, key, plaintext);
  return new Uint8Array(ct);
}

export async function cbcDecrypt(
  key: CryptoKey,
  iv: Uint8Array,
  ciphertext: Uint8Array
): Promise<Uint8Array> {
  const pt = await aesDecrypt({ name: 'AES-CBC', iv }, key, ciphertext);
  return new Uint8Array(pt);
}

function renderChainViz(container: HTMLElement, ciphertext: Uint8Array, iv: Uint8Array): void {
  container.innerHTML = '';
  const ivEl = document.createElement('div');
  ivEl.className = 'chain-block';
  ivEl.textContent = 'IV';
  ivEl.title = hexEncode(iv);
  ivEl.setAttribute('aria-label', `IV: ${hexEncode(iv).slice(0, 16)}…`);
  container.appendChild(ivEl);
  const numBlocks = Math.ceil(ciphertext.length / BLOCK_SIZE);
  for (let i = 0; i < numBlocks; i++) {
    const arrow = document.createElement('span');
    arrow.className = 'chain-arrow';
    arrow.textContent = '→';
    arrow.setAttribute('aria-hidden', 'true');
    container.appendChild(arrow);
    const blockEl = document.createElement('div');
    blockEl.className = 'chain-block';
    const blockHex = hexEncode(ciphertext.slice(i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE));
    blockEl.textContent = `C${i}`;
    blockEl.title = blockHex;
    blockEl.setAttribute('aria-label', `Ciphertext block ${i}: ${blockHex.slice(0, 16)}…`);
    container.appendChild(blockEl);
  }
}

function escapeHtml(s: string): string {
  const div = document.createElement('div');
  div.textContent = s;
  return div.innerHTML;
}

export function mountCBCPanel(): void {
  const plaintextEl = document.getElementById('cbc-plaintext') as HTMLTextAreaElement;
  const ivInput = document.getElementById('cbc-iv') as HTMLInputElement;
  const encryptBtn = document.getElementById('cbc-encrypt-btn') as HTMLButtonElement;
  const ivReuseBtn = document.getElementById('cbc-iv-reuse-btn') as HTMLButtonElement;
  const bitflipBtn = document.getElementById('cbc-bitflip-btn') as HTMLButtonElement;
  const targetedBtn = document.getElementById('cbc-targeted-btn') as HTMLButtonElement;
  const keyOut = document.getElementById('cbc-key') as HTMLElement;
  const ivOut = document.getElementById('cbc-iv-output') as HTMLElement;
  const ctOut = document.getElementById('cbc-ciphertext') as HTMLElement;
  const chainBlocks = document.getElementById('cbc-chain-blocks') as HTMLElement;
  const vulnOutput = document.getElementById('cbc-vuln-output') as HTMLElement;
  const vulnContent = document.getElementById('cbc-vuln-content') as HTMLElement;
  const mathBox = document.getElementById('cbc-math') as HTMLElement;
  const mathRows = document.getElementById('cbc-math-rows') as HTMLElement;
  const decryptSection = document.getElementById('cbc-decrypt-section') as HTMLElement;
  const decryptCorrectBtn = document.getElementById('cbc-decrypt-correct-btn') as HTMLButtonElement;
  const decryptWrongIvBtn = document.getElementById('cbc-decrypt-wrong-iv-btn') as HTMLButtonElement;
  const decryptWrongKeyBtn = document.getElementById('cbc-decrypt-wrong-key-btn') as HTMLButtonElement;
  const decryptTamperBtn = document.getElementById('cbc-decrypt-tamper-btn') as HTMLButtonElement;
  const decryptOutput = document.getElementById('cbc-decrypt-output') as HTMLElement;

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
      const paddedPlaintext = pkcs7Pad(plaintext, BLOCK_SIZE);
      const ciphertext = await cbcEncrypt(key, iv, plaintext);
      const ivHex = hexEncode(iv);
      const ciphertextHex = hexEncode(ciphertext);
      keyOut.textContent = keyHex;
      ivOut.textContent = ivHex;
      ctOut.textContent = ciphertextHex;
      renderChainViz(chainBlocks, ciphertext, iv);
      renderMath(mathRows, cbcMath(paddedPlaintext, iv, ciphertext));
      mathBox.hidden = false;
      lastResult = { key, iv, paddedPlaintext, ciphertext, keyHex, ivHex, ciphertextHex };
      ivReuseBtn.disabled = false;
      bitflipBtn.disabled = false;
      vulnOutput.hidden = true;
      decryptSection.hidden = false;
      decryptOutput.hidden = true;
    } catch (err) {
      announceError(`CBC encryption failed: ${(err as Error).message}`);
    }
  });

  ivReuseBtn.addEventListener('click', async () => {
    if (!lastResult) return;
    try {
      const { key, iv } = lastResult;
      const plaintext = textToBytes(plaintextEl.value || 'Hello, AES-CBC!');
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
      `;
    } catch (err) {
      announceError(`IV reuse demo failed: ${(err as Error).message}`);
    }
  });

  bitflipBtn.addEventListener('click', async () => {
    if (!lastResult) return;
    try {
      const { key, iv, ciphertext } = lastResult;
      const origPlain = await cbcDecrypt(key, iv, ciphertext);
      const origText = bytesToText(origPlain);
      const tampered = new Uint8Array(ciphertext);
      tampered[0] ^= 0x01;
      let decryptedText: string;
      try {
        const decrypted = await cbcDecrypt(key, iv, tampered);
        decryptedText = bytesToText(decrypted);
      } catch {
        decryptedText = '(decryption failed — padding became invalid after bit flip)';
      }
      vulnOutput.hidden = false;
      vulnContent.innerHTML = `
        <p><strong>Bit-flip attack:</strong> Flipped bit 0 of ciphertext byte 0</p>
        <p style="margin-top:0.5rem;">Original plaintext: <code>${escapeHtml(origText)}</code></p>
        <p>After bit flip: <code>${escapeHtml(decryptedText)}</code></p>
        <p style="margin-top:0.5rem;font-weight:700;color:var(--danger)">
          ⚠ Controlled plaintext corruption without knowing the key!
        </p>
      `;
    } catch (err) {
      announceError(`Bit-flip demo failed: ${(err as Error).message}`);
    }
  });

  // Targeted bit-flip puzzle: change admin=0 to admin=1
  targetedBtn.addEventListener('click', async () => {
    try {
      // Plaintext laid out so "admin=0" lands in block 1 — bit-flip block 0 controls it.
      // Block 0 (bytes 0-15):  "userdata=guest--"
      // Block 1 (bytes 16-31): ";admin=0;-------"
      // We want to flip block 1 byte 7 ('0' = 0x30) to ('1' = 0x31) — XOR 0x01.
      // CBC: P1[i] = AES_dec(C1)[i] XOR C0[i]. So flipping C0[7] flips P1[7].
      const plaintextStr = 'userdata=guest--;admin=0;-------';
      const plaintext = textToBytes(plaintextStr);
      const key = await generateCBCKey();
      const iv = crypto.getRandomValues(new Uint8Array(16));
      const ciphertext = await cbcEncrypt(key, iv, plaintext);
      const origPlain = bytesToText(await cbcDecrypt(key, iv, ciphertext));

      // Flip byte index 7 of C0 (which controls byte index 7 of P1, i.e. global index 23 — the '0').
      const tampered = new Uint8Array(ciphertext);
      tampered[7] ^= 0x01;

      let result: string;
      let ok = false;
      try {
        const out = await cbcDecrypt(key, iv, tampered);
        result = bytesToText(out);
        ok = result.includes('admin=1');
      } catch (e) {
        result = `(decrypt failed: ${(e as Error).message})`;
      }

      vulnOutput.hidden = false;
      vulnContent.innerHTML = `
        <p><strong>Targeted bit-flip puzzle:</strong> change <code>admin=0</code> to <code>admin=1</code> without the key.</p>
        <p style="margin-top:0.5rem;font-size:0.85rem;">Plaintext layout (16-byte blocks):</p>
        <div class="hex-output" style="margin:0.3rem 0;">
          [<span style="color:var(--text-muted)">userdata=guest--</span>] [<span style="color:var(--accent);font-weight:700">;admin=0;-------</span>]
        </div>
        <p style="font-size:0.85rem;">In CBC, <code>P₁[i] = AES⁻¹(C₁)[i] ⊕ C₀[i]</code>. To flip bit 0 of P₁[7] (the '0'),
          we flip bit 0 of <strong>C₀[7]</strong>. Block 0 of plaintext is garbled, but block 1 changes <em>exactly</em> as we wanted.</p>
        <p style="margin-top:0.5rem;">Original decrypt: <code>${escapeHtml(origPlain)}</code></p>
        <p>After flipping bit 0 of C₀[1]: <code class="${ok ? 'decrypt-bad-targeted' : ''}">${escapeHtml(result)}</code></p>
        <p style="margin-top:0.5rem;font-weight:700;color:${ok ? 'var(--danger)' : 'var(--warning)'}">
          ${ok ? '⚠ admin=1 — privilege escalation via CBC bit-flip, no key needed.' : '⚠ Block 0 garbled; padding may have collapsed.'}
        </p>
        <p style="font-size:0.82rem;color:var(--text-muted);margin-top:0.4rem;">
          This is exactly why CBC alone must never carry auth-relevant fields. AEAD (GCM/CCM) would have rejected the tampered ciphertext outright.
        </p>
      `;
    } catch (err) {
      announceError(`Targeted bit-flip demo failed: ${(err as Error).message}`);
    }
  });

  // ─── Decrypt demos ──
  decryptCorrectBtn.addEventListener('click', async () => {
    if (!lastResult) return;
    try {
      const pt = await cbcDecrypt(lastResult.key, lastResult.iv, lastResult.ciphertext);
      decryptOutput.hidden = false;
      decryptOutput.innerHTML = `
        <p><strong>Decrypt with correct key + correct IV:</strong></p>
        <code class="decrypt-result decrypt-ok">${escapeHtml(bytesToText(pt))}</code>
        <p class="decrypt-takeaway">✓ Plaintext recovered exactly.</p>
      `;
    } catch (e) {
      decryptOutput.hidden = false;
      decryptOutput.innerHTML = `<p class="decrypt-fail">Decrypt failed: ${escapeHtml((e as Error).message)}</p>`;
    }
  });

  decryptWrongIvBtn.addEventListener('click', async () => {
    if (!lastResult) return;
    const wrongIv = crypto.getRandomValues(new Uint8Array(16));
    try {
      const pt = await cbcDecrypt(lastResult.key, wrongIv, lastResult.ciphertext);
      decryptOutput.hidden = false;
      decryptOutput.innerHTML = `
        <p><strong>Decrypt with WRONG IV (correct key):</strong></p>
        <code class="decrypt-result decrypt-bad">${escapeHtml(bytesToText(pt))}</code>
        <p class="decrypt-takeaway">⚠ Only the FIRST block is garbled; the rest decrypted correctly. The IV only XORs with block 0 — that's why the IV is public, not secret, but must still match for clean recovery.</p>
      `;
    } catch (e) {
      decryptOutput.hidden = false;
      decryptOutput.innerHTML = `
        <p><strong>Decrypt with WRONG IV:</strong></p>
        <p class="decrypt-fail">Decrypt threw (padding rejected): ${escapeHtml((e as Error).message)}. The first block was garbled; padding check on the LAST block fails by coincidence.</p>
      `;
    }
  });

  decryptWrongKeyBtn.addEventListener('click', async () => {
    if (!lastResult) return;
    try {
      const wrongKey = await generateCBCKey();
      const pt = await cbcDecrypt(wrongKey, lastResult.iv, lastResult.ciphertext);
      decryptOutput.hidden = false;
      decryptOutput.innerHTML = `
        <p><strong>Decrypt with WRONG key:</strong></p>
        <code class="decrypt-result decrypt-bad">${escapeHtml(bytesToText(pt))}</code>
        <p class="decrypt-takeaway">⚠ Total garbage — but no integrity error. CBC cannot tell you whether the key was right; it only checks padding.</p>
      `;
    } catch (e) {
      decryptOutput.hidden = false;
      decryptOutput.innerHTML = `
        <p><strong>Decrypt with WRONG key:</strong></p>
        <p class="decrypt-fail">Decrypt threw (padding rejected): ${escapeHtml((e as Error).message)}. Note: this is a padding-validity leak — the basis of the padding oracle attack!</p>
      `;
    }
  });

  decryptTamperBtn.addEventListener('click', async () => {
    if (!lastResult) return;
    const tampered = new Uint8Array(lastResult.ciphertext);
    tampered[0] ^= 0xff;
    try {
      const pt = await cbcDecrypt(lastResult.key, lastResult.iv, tampered);
      decryptOutput.hidden = false;
      decryptOutput.innerHTML = `
        <p><strong>Decrypt with TAMPERED ciphertext (1 byte changed):</strong></p>
        <code class="decrypt-result decrypt-bad">${escapeHtml(bytesToText(pt))}</code>
        <p class="decrypt-takeaway">⚠ CBC returned plaintext anyway. There is no auth tag. With GCM/CCM, this would have been rejected.</p>
      `;
    } catch (e) {
      decryptOutput.hidden = false;
      decryptOutput.innerHTML = `
        <p><strong>Decrypt with TAMPERED ciphertext:</strong></p>
        <p class="decrypt-fail">Decrypt threw (padding rejected by chance): ${escapeHtml((e as Error).message)}.
        That's the padding oracle — the system just told the attacker something about the plaintext.</p>
      `;
    }
  });
}
