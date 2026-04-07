/**
 * ecb.ts — ECB mode implementation
 *
 * WebCrypto does not support ECB natively. We implement ECB by encrypting
 * each 16-byte block individually using AES-CBC with a zero IV. For a
 * single block, AES-CBC with zero IV is mathematically equivalent to ECB:
 *   CBC_enc(key, iv=0, block) = AES_enc(key, block XOR 0) = AES_enc(key, block) = ECB_enc(key, block)
 *
 * We strip the PKCS#7 padding that WebCrypto adds by encrypting with a
 * full 16-byte block input — the output will be 32 bytes (16 block + 16 padding),
 * and we take only the first 16 bytes.
 */

import { hexEncode, textToBytes, pkcs7Pad, aesEncrypt } from './ui';

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

/**
 * Encrypt a single 16-byte block with ECB (via AES-CBC with zero IV).
 */
async function ecbEncryptBlock(key: CryptoKey, block: Uint8Array): Promise<Uint8Array> {
  const ct = await aesEncrypt(
    { name: 'AES-CBC', iv: ZERO_IV },
    key,
    block
  );
  // WebCrypto returns block + padding block (32 bytes); take first 16
  return new Uint8Array(ct).slice(0, BLOCK_SIZE);
}

/**
 * Encrypt plaintext with ECB mode. Applies PKCS#7 padding, then encrypts each block.
 */
export async function ecbEncrypt(key: CryptoKey, plaintext: Uint8Array): Promise<Uint8Array> {
  const padded = pkcs7Pad(plaintext, BLOCK_SIZE);
  const numBlocks = padded.length / BLOCK_SIZE;
  const ciphertext = new Uint8Array(padded.length);

  for (let i = 0; i < numBlocks; i++) {
    const block = padded.slice(i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE);
    const encBlock = await ecbEncryptBlock(key, block);
    ciphertext.set(encBlock, i * BLOCK_SIZE);
  }

  return ciphertext;
}

/**
 * Encrypt image pixel data with ECB to demonstrate pattern leakage.
 */
export async function ecbEncryptImageData(
  key: CryptoKey,
  imageData: ImageData
): Promise<ImageData> {
  const pixels = new Uint8Array(imageData.data.buffer);
  // Encrypt RGB bytes only (skip alpha), in 16-byte blocks
  const rgbBytes: number[] = [];
  for (let i = 0; i < pixels.length; i += 4) {
    rgbBytes.push(pixels[i], pixels[i + 1], pixels[i + 2]);
  }

  const rgbArray = new Uint8Array(rgbBytes);
  // Pad to block boundary
  const padded = pkcs7Pad(rgbArray, BLOCK_SIZE);
  const encrypted = new Uint8Array(padded.length);

  const numBlocks = padded.length / BLOCK_SIZE;
  for (let i = 0; i < numBlocks; i++) {
    const block = padded.slice(i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE);
    const enc = await ecbEncryptBlock(key, block);
    encrypted.set(enc, i * BLOCK_SIZE);
  }

  // Reconstruct image data from encrypted RGB + original alpha
  const result = new ImageData(imageData.width, imageData.height);
  let rgbIdx = 0;
  for (let i = 0; i < result.data.length; i += 4) {
    result.data[i] = encrypted[rgbIdx] ?? 0;
    result.data[i + 1] = encrypted[rgbIdx + 1] ?? 0;
    result.data[i + 2] = encrypted[rgbIdx + 2] ?? 0;
    result.data[i + 3] = 255; // full alpha
    rgbIdx += 3;
  }

  return result;
}

/**
 * Compare ciphertext blocks and return block-level info for visualization.
 */
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
    if (!positions.has(blockHex)) {
      positions.set(blockHex, []);
    }
    positions.get(blockHex)!.push(idx);
  }

  const duplicates = new Map<string, number[]>();
  for (const [hex, indices] of positions) {
    if (indices.length > 1) {
      duplicates.set(hex, indices);
    }
  }

  return { blocks, duplicates };
}

/**
 * Mount ECB panel interactivity.
 */
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

  let currentKey: CryptoKey | null = null;

  encryptBtn.addEventListener('click', async () => {
    try {
      currentKey = await generateECBKey();
      keyOut.textContent = await exportKeyHex(currentKey);

      // Check if image was uploaded
      if (imageInput.files && imageInput.files.length > 0) {
        await handleImageEncrypt(currentKey, imageInput.files[0]);
        return;
      }

      // Text encryption
      const text = plaintextEl.value || 'YELLOW SUBMARINEYELLOW SUBMARINE';
      const plainBytes = textToBytes(text);
      const ciphertext = await ecbEncrypt(currentKey, plainBytes);

      ctOut.textContent = hexEncode(ciphertext);

      // Visualize blocks
      const { blocks, duplicates } = analyzeBlocks(ciphertext);
      renderBlockGrid(blockGrid, blocks, duplicates);
      imageOutput.hidden = true;
    } catch (err) {
      announceError(`ECB encryption failed: ${(err as Error).message}`);
    }
  });

  async function handleImageEncrypt(key: CryptoKey, file: File): Promise<void> {
    const img = new Image();
    const url = URL.createObjectURL(file);

    img.onload = async () => {
      URL.revokeObjectURL(url);
      // Scale down for performance
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

  // Assign colors to unique blocks
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
    cell.title = hex.slice(0, 8) + '…';
    cell.setAttribute('aria-label', `Block ${i}: ${hex.slice(0, 16)}…`);

    // Mark duplicates
    const isDup = duplicates.has(hex);
    if (isDup) {
      cell.setAttribute('data-duplicate', 'true');
      cell.title += ' (DUPLICATE — structure leaked!)';
    }

    container.appendChild(cell);
  });
}

function announceError(msg: string): void {
  const region = document.getElementById('error-region');
  if (region) region.textContent = msg;
}
