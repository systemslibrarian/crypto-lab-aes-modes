/**
 * ecb.ts — ECB mode implementation + decryption/tamper demo
 *
 * WebCrypto does not support ECB. Encryption uses AES-CBC with zero IV per
 * block. Decryption uses @noble/ciphers ECB (disablePadding) since the same
 * single-block trick doesn't reverse cleanly with WebCrypto's padding.
 */

import { ecb as nobleEcb } from '@noble/ciphers/aes';
import {
  hexEncode,
  textToBytes,
  bytesToText,
  pkcs7Pad,
  aesEncrypt,
  announceError,
} from './ui';
import { ecbMath, renderMath } from './helpers';

const BLOCK_SIZE = 16;
const ZERO_IV = new Uint8Array(16);

export async function generateECBKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: 'AES-CBC', length: 128 },
    true,
    ['encrypt', 'decrypt']
  );
}

export async function exportKeyHex(key: CryptoKey): Promise<string> {
  const raw = await crypto.subtle.exportKey('raw', key);
  return hexEncode(new Uint8Array(raw));
}

async function ecbEncryptBlock(key: CryptoKey, block: Uint8Array): Promise<Uint8Array> {
  const ct = await aesEncrypt({ name: 'AES-CBC', iv: ZERO_IV }, key, block);
  return new Uint8Array(ct).slice(0, BLOCK_SIZE);
}

export async function ecbEncrypt(key: CryptoKey, plaintext: Uint8Array): Promise<Uint8Array> {
  const padded = pkcs7Pad(plaintext, BLOCK_SIZE);
  const numBlocks = padded.length / BLOCK_SIZE;
  const ciphertext = new Uint8Array(padded.length);
  for (let i = 0; i < numBlocks; i++) {
    const block = padded.slice(i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE);
    const enc = await ecbEncryptBlock(key, block);
    ciphertext.set(enc, i * BLOCK_SIZE);
  }
  return ciphertext;
}

async function ecbDecrypt(key: CryptoKey, ciphertext: Uint8Array): Promise<Uint8Array> {
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', key));
  const cipher = nobleEcb(raw, { disablePadding: true });
  const padded = cipher.decrypt(ciphertext);
  const last = padded[padded.length - 1];
  if (last > 0 && last <= BLOCK_SIZE) {
    return padded.slice(0, padded.length - last);
  }
  return padded;
}

export async function ecbEncryptImageData(
  key: CryptoKey,
  imageData: ImageData
): Promise<ImageData> {
  const pixels = new Uint8Array(imageData.data.buffer);
  const rgbArray = new Uint8Array((pixels.length / 4) * 3);
  let rgbInIdx = 0;
  for (let i = 0; i < pixels.length; i += 4) {
    rgbArray[rgbInIdx++] = pixels[i];
    rgbArray[rgbInIdx++] = pixels[i + 1];
    rgbArray[rgbInIdx++] = pixels[i + 2];
  }
  const padded = pkcs7Pad(rgbArray, BLOCK_SIZE);
  const encrypted = new Uint8Array(padded.length);
  const numBlocks = padded.length / BLOCK_SIZE;
  for (let i = 0; i < numBlocks; i++) {
    const block = padded.slice(i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE);
    const enc = await ecbEncryptBlock(key, block);
    encrypted.set(enc, i * BLOCK_SIZE);
  }
  const result = new ImageData(imageData.width, imageData.height);
  let rgbIdx = 0;
  for (let i = 0; i < result.data.length; i += 4) {
    result.data[i] = encrypted[rgbIdx] ?? 0;
    result.data[i + 1] = encrypted[rgbIdx + 1] ?? 0;
    result.data[i + 2] = encrypted[rgbIdx + 2] ?? 0;
    result.data[i + 3] = 255;
    rgbIdx += 3;
  }
  return result;
}

export function analyzeBlocks(ciphertext: Uint8Array): {
  blocks: string[];
  duplicates: Map<string, number[]>;
} {
  const blocks: string[] = [];
  const positions = new Map<string, number[]>();
  for (let i = 0; i < ciphertext.length; i += BLOCK_SIZE) {
    const blockHex = hexEncode(ciphertext.slice(i, i + BLOCK_SIZE));
    blocks.push(blockHex);
    const idx = i / BLOCK_SIZE;
    if (!positions.has(blockHex)) positions.set(blockHex, []);
    positions.get(blockHex)!.push(idx);
  }
  const duplicates = new Map<string, number[]>();
  for (const [hex, indices] of positions) {
    if (indices.length > 1) duplicates.set(hex, indices);
  }
  return { blocks, duplicates };
}

function escapeHtml(s: string): string {
  const div = document.createElement('div');
  div.textContent = s;
  return div.innerHTML;
}

export function mountECBPanel(): void {
  const plaintextEl = document.getElementById('ecb-plaintext') as HTMLTextAreaElement;
  const imageInput = document.getElementById('ecb-image-upload') as HTMLInputElement;
  const encryptBtn = document.getElementById('ecb-encrypt-btn') as HTMLButtonElement;
  const keyOut = document.getElementById('ecb-key') as HTMLElement;
  const ctOut = document.getElementById('ecb-ciphertext') as HTMLElement;
  const blockGrid = document.getElementById('ecb-block-grid') as HTMLElement;
  const imageOutput = document.getElementById('ecb-image-output') as HTMLElement;
  const canvasOrig = document.getElementById('ecb-canvas-original') as HTMLCanvasElement;
  const canvasEnc = document.getElementById('ecb-canvas-encrypted') as HTMLCanvasElement;
  const mathBox = document.getElementById('ecb-math') as HTMLElement;
  const mathRows = document.getElementById('ecb-math-rows') as HTMLElement;
  const decryptSection = document.getElementById('ecb-decrypt-section') as HTMLElement;
  const decryptBtn = document.getElementById('ecb-decrypt-btn') as HTMLButtonElement;
  const decryptTamperBtn = document.getElementById('ecb-decrypt-tamper-btn') as HTMLButtonElement;
  const decryptOutput = document.getElementById('ecb-decrypt-output') as HTMLElement;

  let currentKey: CryptoKey | null = null;
  let currentCiphertext: Uint8Array | null = null;
  let currentPaddedPlaintext: Uint8Array | null = null;

  encryptBtn.addEventListener('click', async () => {
    try {
      currentKey = await generateECBKey();
      keyOut.textContent = await exportKeyHex(currentKey);

      if (imageInput.files && imageInput.files.length > 0) {
        await handleImageEncrypt(currentKey, imageInput.files[0]);
        mathBox.hidden = true;
        decryptSection.hidden = true;
        return;
      }

      const text = plaintextEl.value || 'YELLOW SUBMARINEYELLOW SUBMARINE';
      const plainBytes = textToBytes(text);
      const padded = pkcs7Pad(plainBytes, BLOCK_SIZE);
      const ciphertext = await ecbEncrypt(currentKey, plainBytes);

      currentCiphertext = ciphertext;
      currentPaddedPlaintext = padded;

      ctOut.textContent = hexEncode(ciphertext);

      const { blocks, duplicates } = analyzeBlocks(ciphertext);
      renderBlockGrid(blockGrid, blocks, duplicates);
      imageOutput.hidden = true;

      renderMath(mathRows, ecbMath(padded, ciphertext));
      mathBox.hidden = false;
      decryptSection.hidden = false;
      decryptOutput.hidden = true;
    } catch (err) {
      announceError(`ECB encryption failed: ${(err as Error).message}`);
    }
  });

  decryptBtn.addEventListener('click', async () => {
    if (!currentKey || !currentCiphertext) return;
    try {
      const pt = await ecbDecrypt(currentKey, currentCiphertext);
      decryptOutput.hidden = false;
      decryptOutput.innerHTML = `
        <p><strong>Decrypted with correct key:</strong></p>
        <code class="decrypt-result decrypt-ok">${escapeHtml(bytesToText(pt))}</code>
        <p class="decrypt-takeaway">✓ Round-trip works. But notice: ECB will also "succeed" on tampered ciphertext — there's no integrity check.</p>
      `;
    } catch (err) {
      decryptOutput.hidden = false;
      decryptOutput.innerHTML = `<p class="decrypt-fail">Decrypt failed: ${escapeHtml((err as Error).message)}</p>`;
    }
  });

  decryptTamperBtn.addEventListener('click', async () => {
    if (!currentKey || !currentCiphertext) return;
    try {
      const tampered = new Uint8Array(currentCiphertext);
      // Flip an entire byte of the first ciphertext block — that block decrypts to garbage,
      // other blocks remain intact (no chaining in ECB).
      tampered[0] ^= 0xff;
      const pt = await ecbDecrypt(currentKey, tampered);
      decryptOutput.hidden = false;
      decryptOutput.innerHTML = `
        <p><strong>Decrypted after corrupting 1 byte of ciphertext block 0:</strong></p>
        <code class="decrypt-result decrypt-bad">${escapeHtml(bytesToText(pt))}</code>
        <p class="decrypt-takeaway">⚠ ECB returns plaintext without error. Block 0 is garbage; the rest is intact (no chaining). With GCM/CCM, the decrypt would have been REJECTED.</p>
      `;
    } catch (err) {
      decryptOutput.hidden = false;
      decryptOutput.innerHTML = `
        <p><strong>Decrypted after corrupting 1 byte of ciphertext block 0:</strong></p>
        <p class="decrypt-fail">Decrypt threw: ${escapeHtml((err as Error).message)} (PKCS#7 unpad rejected — but other tampering would succeed silently).</p>
      `;
    }
  });

  async function handleImageEncrypt(key: CryptoKey, file: File): Promise<void> {
    const img = new Image();
    const url = URL.createObjectURL(file);
    img.onload = async () => {
      URL.revokeObjectURL(url);
      const maxDim = 128;
      const scale = Math.min(maxDim / img.width, maxDim / img.height, 1);
      const w = Math.round(img.width * scale);
      const h = Math.round(img.height * scale);
      canvasOrig.width = w;
      canvasOrig.height = h;
      const ctxOrig = canvasOrig.getContext('2d')!;
      ctxOrig.drawImage(img, 0, 0, w, h);
      const origData = ctxOrig.getImageData(0, 0, w, h);
      const encData = await ecbEncryptImageData(key, origData);
      canvasEnc.width = w;
      canvasEnc.height = h;
      const ctxEnc = canvasEnc.getContext('2d')!;
      ctxEnc.putImageData(encData, 0, 0);
      imageOutput.hidden = false;
      ctOut.textContent = '(see image visualization below)';
      blockGrid.innerHTML = '';
    };
    img.src = url;
  }
}

function renderBlockGrid(
  container: HTMLElement,
  blocks: string[],
  duplicates: Map<string, number[]>
): void {
  container.innerHTML = '';
  const colorMap = new Map<string, string>();
  const palette = [
    '#3b82f6', '#8b5cf6', '#06b6d4', '#10b981', '#f59e0b',
    '#ef4444', '#ec4899', '#6366f1', '#14b8a6', '#f97316',
  ];
  let colorIdx = 0;
  for (const hex of blocks) {
    if (!colorMap.has(hex)) {
      colorMap.set(hex, palette[colorIdx % palette.length]);
      colorIdx++;
    }
  }
  blocks.forEach((hex, i) => {
    const cell = document.createElement('div');
    cell.className = 'block-cell';
    cell.style.backgroundColor = colorMap.get(hex)!;
    cell.textContent = `B${i}`;
    // `title` only — an aria-label here is prohibited on a role-less <div> and
    // would be discarded regardless, because `container` is role="img" and
    // makes its whole subtree presentational. The information belongs on the
    // container, and is set below.
    cell.title = hex.slice(0, 8) + '…';
    const isDup = duplicates.has(hex);
    if (isDup) {
      cell.setAttribute('data-duplicate', 'true');
      cell.title += ' (DUPLICATE — structure leaked!)';
    }
    container.appendChild(cell);
  });

  // The grid is the accessible object, so its name has to carry the finding —
  // not a fixed "Visual block comparison" that says the same thing whether ECB
  // leaked the structure of the message or not.
  const repeated = [...duplicates.values()];
  const total = repeated.reduce((n, idx) => n + idx.length, 0);
  container.setAttribute(
    'aria-label',
    repeated.length === 0
      ? `${blocks.length} ciphertext blocks, all different.`
      : `${blocks.length} ciphertext blocks. ${total} of them repeat, in ` +
        `${repeated.length} group${repeated.length === 1 ? '' : 's'}: ` +
        repeated.map((idx) => `blocks ${idx.join(' and ')}`).join('; ') +
        '. That repetition is the structure ECB leaks.'
  );
}
