/**
 * compare.ts — Same-plaintext, all-five-modes side-by-side renderer.
 *
 * Encrypts the same input under ECB, CBC, CTR, GCM, CCM with fresh random
 * key/nonce per mode, then draws each ciphertext as a block grid so students
 * can SEE that only ECB leaks repeated blocks.
 */

import { ecbEncrypt, generateECBKey, analyzeBlocks } from './ecb';
import { cbcEncrypt } from './cbc';
import { ctrEncrypt } from './ctr';
import { gcmEncrypt } from './gcm';
import { ccmEncrypt } from './ccm';
import { hexEncode, textToBytes, announceError } from './ui';

const BLOCK_SIZE = 16;

const PALETTE = [
  '#3b82f6', '#8b5cf6', '#06b6d4', '#10b981', '#f59e0b',
  '#ef4444', '#ec4899', '#6366f1', '#14b8a6', '#f97316',
  '#a855f7', '#0ea5e9', '#84cc16', '#eab308', '#f43f5e',
];

function renderGrid(container: HTMLElement, ct: Uint8Array): { dupCount: number } {
  const { blocks, duplicates } = analyzeBlocks(ct.length % BLOCK_SIZE === 0 ? ct : padForGrid(ct));
  const colorMap = new Map<string, string>();
  let colorIdx = 0;
  for (const hex of blocks) {
    if (!colorMap.has(hex)) {
      colorMap.set(hex, PALETTE[colorIdx % PALETTE.length]);
      colorIdx++;
    }
  }
  blocks.forEach((hex, i) => {
    const cell = document.createElement('div');
    cell.className = 'block-cell';
    cell.style.backgroundColor = colorMap.get(hex)!;
    cell.textContent = `B${i}`;
    cell.title = hex.slice(0, 16) + '…';
    if (duplicates.has(hex)) cell.setAttribute('data-duplicate', 'true');
    container.appendChild(cell);
  });
  container.setAttribute('role', 'img');
  container.setAttribute(
    'aria-label',
    duplicates.size === 0
      ? `${blocks.length} ciphertext blocks, all different.`
      : `${blocks.length} ciphertext blocks, with ${duplicates.size} group` +
        `${duplicates.size === 1 ? '' : 's'} of repeats — structure leaked.`
  );
  return { dupCount: duplicates.size };
}

function padForGrid(ct: Uint8Array): Uint8Array {
  const n = Math.ceil(ct.length / BLOCK_SIZE) * BLOCK_SIZE;
  const out = new Uint8Array(n);
  out.set(ct);
  return out;
}

interface ModeCard {
  name: string;
  status: 'avoid' | 'legacy' | 'ok' | 'recommended';
  ciphertext: Uint8Array;
  note: string;
}

function appendCard(container: HTMLElement, card: ModeCard): void {
  const wrapper = document.createElement('div');
  wrapper.className = 'compare-card';
  wrapper.innerHTML = `
    <div class="compare-card-head">
      <h3>${card.name}</h3>
      <span class="status-chip status-${card.status}">${card.status.toUpperCase()}</span>
    </div>
    <div class="compare-grid-row"></div>
    <p class="compare-card-note">${card.note}</p>
    <details>
      <summary>ciphertext hex</summary>
      <div class="hex-output" tabindex="0" role="group" aria-label="${card.name} ciphertext, hexadecimal">${hexEncode(card.ciphertext)}</div>
    </details>
  `;
  container.appendChild(wrapper);
  const row = wrapper.querySelector<HTMLElement>('.compare-grid-row')!;
  const { dupCount } = renderGrid(row, card.ciphertext);
  if (dupCount > 0) {
    const warn = document.createElement('p');
    warn.className = 'compare-dup-warn';
    warn.textContent = `⚠ ${dupCount} duplicate block group(s) — structure leaked.`;
    wrapper.insertBefore(warn, wrapper.querySelector('details'));
  }
}

export function mountComparePanel(): void {
  const ptEl = document.getElementById('compare-plaintext') as HTMLTextAreaElement | null;
  const btn = document.getElementById('compare-btn') as HTMLButtonElement | null;
  const out = document.getElementById('compare-output') as HTMLElement | null;
  if (!ptEl || !btn || !out) return;

  btn.addEventListener('click', async () => {
    try {
      out.innerHTML = '';
      const text = ptEl.value || 'YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE';
      const pt = textToBytes(text);

      const ecbKey = await generateECBKey();
      const ecbCt = await ecbEncrypt(ecbKey, pt);

      const cbcKey = await crypto.subtle.generateKey({ name: 'AES-CBC', length: 256 }, true, ['encrypt', 'decrypt']);
      const cbcIv = crypto.getRandomValues(new Uint8Array(16));
      const cbcCt = await cbcEncrypt(cbcKey, cbcIv, pt);

      const ctrKey = await crypto.subtle.generateKey({ name: 'AES-CTR', length: 256 }, true, ['encrypt', 'decrypt']);
      const ctrNonce = crypto.getRandomValues(new Uint8Array(12));
      const ctrCounter = new Uint8Array(16);
      ctrCounter.set(ctrNonce.slice(0, 12));
      ctrCounter[15] = 1;
      const ctrCt = await ctrEncrypt(ctrKey, ctrCounter, pt);

      const gcmKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
      const gcmNonce = crypto.getRandomValues(new Uint8Array(12));
      const { ciphertext: gcmCt } = await gcmEncrypt(gcmKey, gcmNonce, pt, new Uint8Array(0), 128);

      const ccmKey = crypto.getRandomValues(new Uint8Array(16));
      const ccmNonce = crypto.getRandomValues(new Uint8Array(13));
      const ccmFull = ccmEncrypt(ccmKey, ccmNonce, pt, new Uint8Array(0), 16);
      const ccmCt = ccmFull.slice(0, ccmFull.length - 16);

      appendCard(out, {
        name: 'ECB',
        status: 'avoid',
        ciphertext: ecbCt,
        note: 'No IV, no chaining. Same plaintext block → same ciphertext block. Watch for duplicates.',
      });
      appendCard(out, {
        name: 'CBC',
        status: 'legacy',
        ciphertext: cbcCt,
        note: 'Each block XORed with previous ciphertext. No repeats — but no integrity either.',
      });
      appendCard(out, {
        name: 'CTR',
        status: 'ok',
        ciphertext: ctrCt,
        note: 'Plaintext XOR keystream(counter). No repeats. Length is preserved exactly.',
      });
      appendCard(out, {
        name: 'GCM',
        status: 'recommended',
        ciphertext: gcmCt,
        note: 'CTR-based encryption + authentication tag (not shown above). AEAD.',
      });
      appendCard(out, {
        name: 'CCM',
        status: 'ok',
        ciphertext: ccmCt,
        note: 'CTR-based encryption + CBC-MAC tag (not shown above). AEAD.',
      });
    } catch (err) {
      announceError(`Compare failed: ${(err as Error).message}`);
    }
  });
}
