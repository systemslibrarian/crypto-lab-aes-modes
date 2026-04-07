/**
 * ctr.ts — CTR mode implementation with nonce reuse demo
 *
 * Uses WebCrypto AES-CTR (AES-256). Demonstrates:
 * - Counter block construction and keystream XOR
 * - Nonce reuse attack: C1 ⊕ C2 = P1 ⊕ P2
 */

import { hexEncode, textToBytes, bytesToText, announceError, aesEncrypt } from './ui';

async function generateCTRKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: 'AES-CTR', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

async function exportKeyHex(key: CryptoKey): Promise<string> {
  const raw = await crypto.subtle.exportKey('raw', key);
  return hexEncode(new Uint8Array(raw));
}

/**
 * Build a 16-byte counter block: 12-byte nonce + 4-byte big-endian counter starting at 1.
 */
function makeCounter(nonce: Uint8Array): Uint8Array {
  const counter = new Uint8Array(16);
  counter.set(nonce.slice(0, 12));
  // Counter starts at 1 (big-endian in last 4 bytes)
  counter[15] = 1;
  return counter;
}

export async function ctrEncrypt(
  key: CryptoKey,
  counter: Uint8Array,
  plaintext: Uint8Array
): Promise<Uint8Array> {
  const ct = await aesEncrypt(
    { name: 'AES-CTR', counter, length: 32 }, // 32 bits of counter
    key,
    plaintext
  );
  return new Uint8Array(ct);
}

function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const len = Math.min(a.length, b.length);
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    out[i] = a[i] ^ b[i];
  }
  return out;
}

function renderStreamViz(
  container: HTMLElement,
  nonce: Uint8Array,
  ciphertext: Uint8Array
): void {
  container.innerHTML = '';
  const BLOCK = 16;
  const numBlocks = Math.ceil(ciphertext.length / BLOCK);

  for (let i = 0; i < Math.min(numBlocks, 4); i++) {
    const row = document.createElement('div');
    row.className = 'stream-row';

    // Counter label
    const label = document.createElement('span');
    label.className = 'stream-label';
    label.textContent = `CTR[${i}]:`;
    row.appendChild(label);

    // Nonce portion
    const nonceCell = document.createElement('span');
    nonceCell.className = 'stream-cell';
    nonceCell.textContent = hexEncode(nonce).slice(0, 12) + '…';
    nonceCell.title = 'Nonce (12 bytes)';
    row.appendChild(nonceCell);

    // + counter
    const plus = document.createElement('span');
    plus.textContent = '|';
    plus.setAttribute('aria-hidden', 'true');
    row.appendChild(plus);

    const ctrCell = document.createElement('span');
    ctrCell.className = 'stream-cell';
    ctrCell.textContent = (i + 1).toString().padStart(8, '0');
    ctrCell.title = `Counter value: ${i + 1}`;
    row.appendChild(ctrCell);

    // → AES → keystream → ⊕ P → C
    const arrow = document.createElement('span');
    arrow.textContent = ' → AES → ⊕ P → ';
    arrow.style.fontSize = '0.72rem';
    arrow.style.color = 'var(--text-muted)';
    arrow.setAttribute('aria-label', 'encrypts to keystream, XORed with plaintext, producing');
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

  let currentKey: CryptoKey | null = null;
  let currentNonce: Uint8Array | null = null;
  let currentCounter: Uint8Array | null = null;

  encryptBtn.addEventListener('click', async () => {
    try {
      currentKey = await generateCTRKey();
      currentNonce = crypto.getRandomValues(new Uint8Array(12));
      currentCounter = makeCounter(currentNonce);

      const keyHex = await exportKeyHex(currentKey);
      keyOut.textContent = keyHex;
      counterOut.textContent = hexEncode(currentCounter);

      const plain = textToBytes(pt1El.value || 'AES-CTR encrypts by XORing with a keystream.');
      const ct = await ctrEncrypt(currentKey, currentCounter, plain);
      ctOut.textContent = hexEncode(ct);

      renderStreamViz(streamBlocks, currentNonce, ct);

      nonceReuseBtn.disabled = false;
      nonceOutput.hidden = true;
    } catch (err) {
      announceError(`CTR encryption failed: ${(err as Error).message}`);
    }
  });

  nonceReuseBtn.addEventListener('click', async () => {
    if (!currentKey || !currentCounter) return;
    try {
      const p1 = textToBytes(pt1El.value || 'AES-CTR encrypts by XORing with a keystream.');
      const p2 = textToBytes(pt2El.value || 'This is a different secret message!');

      // Encrypt BOTH with the SAME nonce — catastrophic!
      const c1 = await ctrEncrypt(currentKey, currentCounter, p1);
      const c2 = await ctrEncrypt(currentKey, currentCounter, p2);

      // XOR ciphertexts → P1 ⊕ P2 (keystream cancels)
      const xored = xorBytes(c1, c2);

      // If attacker knows P1, they recover P2
      const recoveredP2 = xorBytes(xored, p1);
      const recoveredText = bytesToText(recoveredP2.slice(0, p2.length));

      nonceOutput.hidden = false;
      nonceContent.innerHTML = `
        <p><strong>Both messages encrypted with the same nonce:</strong></p>
        <p style="font-size:0.82rem;">C₁ = Enc(key, nonce, P₁)</p>
        <p style="font-size:0.82rem;">C₂ = Enc(key, nonce, P₂)</p>
        <p style="font-size:0.82rem;margin-top:0.4rem;"><strong>C₁ ⊕ C₂ = P₁ ⊕ P₂</strong> (keystream cancels!)</p>
        <div style="margin:0.5rem 0;">
          <p style="font-size:0.78rem;color:var(--text-muted);">C₁ ⊕ C₂ (hex):</p>
          <div class="hex-output">${hexEncode(xored)}</div>
        </div>
        <p style="margin-top:0.5rem;"><strong>If attacker knows P₁, they recover P₂:</strong></p>
        <p style="font-size:0.82rem;">(P₁ ⊕ P₂) ⊕ P₁ = P₂</p>
        <div class="hex-output" style="margin-top:0.3rem;font-weight:700;color:var(--danger);">
          ${escapeHtml(recoveredText)}
        </div>
        <p style="margin-top:0.5rem;font-weight:700;color:var(--danger);">
          ⚠ Full plaintext recovered! Nonce reuse destroys CTR security.
        </p>
        <p style="font-size:0.82rem;color:var(--text-muted);margin-top:0.3rem;">
          Text equivalent: VULNERABILITY — nonce reuse allows full plaintext recovery via XOR
        </p>
      `;
    } catch (err) {
      announceError(`Nonce reuse demo failed: ${(err as Error).message}`);
    }
  });
}

function escapeHtml(s: string): string {
  const div = document.createElement('div');
  div.textContent = s;
  return div.innerHTML;
}
