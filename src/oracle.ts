/**
 * oracle.ts — Padding Oracle Attack Engine
 *
 * Implements a real CBC padding oracle attack. The oracle validates PKCS#7
 * padding and returns only valid/invalid — no other information.
 *
 * The attack recovers plaintext one byte at a time by manipulating the
 * previous ciphertext block and observing padding validity responses.
 *
 * This is a REAL attack demonstration: the bit-flipping and padding
 * validation are genuine — no simulated or fake responses.
 */

import { hexEncode, textToBytes, bytesToText, announceError, aesEncrypt, aesDecrypt } from './ui';

const BLOCK_SIZE = 16;

/**
 * PKCS#7 padding oracle: returns true if padding is valid, false otherwise.
 * Uses WebCrypto AES-CBC decrypt — if padding is invalid, decrypt throws.
 */
async function paddingOracle(key: CryptoKey, iv: Uint8Array, ciphertext: Uint8Array): Promise<boolean> {
  try {
    await aesDecrypt({ name: 'AES-CBC', iv }, key, ciphertext);
    return true;
  } catch {
    return false;
  }
}

/**
 * Encrypt plaintext with AES-256-CBC and return key, IV, and ciphertext.
 */
async function setupTarget(plaintext: Uint8Array): Promise<{
  key: CryptoKey;
  iv: Uint8Array;
  ciphertext: Uint8Array;
}> {
  const key = await crypto.subtle.generateKey(
    { name: 'AES-CBC', length: 256 },
    false, // non-extractable for attack realism
    ['encrypt', 'decrypt']
  );
  const iv = crypto.getRandomValues(new Uint8Array(16));

  const ct = await aesEncrypt({ name: 'AES-CBC', iv }, key, plaintext);
  return { key, iv, ciphertext: new Uint8Array(ct) };
}

export interface OracleCallbacks {
  onByteStart: (blockIdx: number, byteIdx: number) => void;
  onQuery: (queryNum: number, guess: number, valid: boolean) => void;
  onByteRecovered: (blockIdx: number, byteIdx: number, value: number, char: string) => void;
  onBlockComplete: (blockIdx: number, plaintext: Uint8Array) => void;
  onComplete: (fullPlaintext: Uint8Array) => void;
}

/**
 * Run the padding oracle attack on a single block.
 *
 * To decrypt block C[blockIdx], we manipulate the previous block
 * (or IV for blockIdx=0) and send [modified_prev | C[blockIdx]] to the oracle.
 *
 * For each byte position (15 down to 0):
 *   1. Set known bytes to produce desired padding
 *   2. Brute-force the target byte (0-255)
 *   3. When padding is valid, we learn the intermediate value
 *   4. XOR with original prev byte to get plaintext byte
 */
async function attackBlock(
  key: CryptoKey,
  prevBlock: Uint8Array,
  targetBlock: Uint8Array,
  blockIdx: number,
  callbacks: OracleCallbacks
): Promise<{ plaintext: Uint8Array; queryCount: number }> {
  const intermediate = new Uint8Array(BLOCK_SIZE);
  const plaintext = new Uint8Array(BLOCK_SIZE);
  let queryCount = 0;

  for (let bytePos = BLOCK_SIZE - 1; bytePos >= 0; bytePos--) {
    const padValue = BLOCK_SIZE - bytePos; // target padding value
    callbacks.onByteStart(blockIdx, bytePos);

    // Build the attack block: set already-known bytes to produce padValue
    const attackPrev = new Uint8Array(BLOCK_SIZE);
    for (let k = bytePos + 1; k < BLOCK_SIZE; k++) {
      attackPrev[k] = intermediate[k] ^ padValue;
    }

    let found = false;
    for (let guess = 0; guess < 256; guess++) {
      attackPrev[bytePos] = guess;

      // Send [attackPrev | targetBlock] to oracle
      const testCt = new Uint8Array(BLOCK_SIZE);
      testCt.set(targetBlock);

      const valid = await paddingOracle(key, attackPrev, testCt);
      queryCount++;
      callbacks.onQuery(queryCount, guess, valid);

      if (valid) {
        // Disambiguate: for the last byte, a valid padding might be 0x01
        // or a longer padding by coincidence. Check by flipping an earlier byte.
        if (bytePos === BLOCK_SIZE - 1 && padValue === 1) {
          const check = new Uint8Array(attackPrev);
          if (bytePos > 0) {
            check[bytePos - 1] ^= 0x01;
          }
          const stillValid = await paddingOracle(key, check, testCt);
          queryCount++;
          if (!stillValid) {
            continue; // false positive — padding was longer than 0x01
          }
        }

        intermediate[bytePos] = guess ^ padValue;
        plaintext[bytePos] = intermediate[bytePos] ^ prevBlock[bytePos];

        const char = plaintext[bytePos] >= 32 && plaintext[bytePos] < 127
          ? String.fromCharCode(plaintext[bytePos])
          : '.';
        callbacks.onByteRecovered(blockIdx, bytePos, plaintext[bytePos], char);
        found = true;
        break;
      }
    }

    if (!found) {
      // Should not happen in a correct implementation
      intermediate[bytePos] = 0;
      plaintext[bytePos] = prevBlock[bytePos];
    }
  }

  callbacks.onBlockComplete(blockIdx, plaintext);
  return { plaintext, queryCount };
}

/**
 * Run the full padding oracle attack across all blocks.
 */
async function runAttack(
  key: CryptoKey,
  iv: Uint8Array,
  ciphertext: Uint8Array,
  callbacks: OracleCallbacks
): Promise<{ plaintext: Uint8Array; totalQueries: number }> {
  const numBlocks = ciphertext.length / BLOCK_SIZE;
  const fullPlaintext = new Uint8Array(ciphertext.length);
  let totalQueries = 0;

  for (let b = 0; b < numBlocks; b++) {
    const prevBlock = b === 0 ? iv : ciphertext.slice((b - 1) * BLOCK_SIZE, b * BLOCK_SIZE);
    const targetBlock = ciphertext.slice(b * BLOCK_SIZE, (b + 1) * BLOCK_SIZE);

    const { plaintext, queryCount } = await attackBlock(key, prevBlock, targetBlock, b, callbacks);
    fullPlaintext.set(plaintext, b * BLOCK_SIZE);
    totalQueries += queryCount;

    // Yield to UI between blocks
    await new Promise(r => setTimeout(r, 0));
  }

  // Strip PKCS#7 padding from result
  const lastByte = fullPlaintext[fullPlaintext.length - 1];
  const unpaddedLen = (lastByte > 0 && lastByte <= BLOCK_SIZE)
    ? fullPlaintext.length - lastByte
    : fullPlaintext.length;
  const result = fullPlaintext.slice(0, unpaddedLen);

  callbacks.onComplete(result);
  return { plaintext: result, totalQueries };
}

export function mountOraclePanel(): void {
  const plaintextEl = document.getElementById('oracle-plaintext') as HTMLTextAreaElement;
  const setupBtn = document.getElementById('oracle-setup-btn') as HTMLButtonElement;
  const runBtn = document.getElementById('oracle-run-btn') as HTMLButtonElement;
  const autoBtn = document.getElementById('oracle-auto-btn') as HTMLButtonElement;
  const ctOut = document.getElementById('oracle-ciphertext') as HTMLElement;
  const progressDiv = document.getElementById('oracle-progress') as HTMLElement;
  const blockNumOut = document.getElementById('oracle-block-num') as HTMLElement;
  const byteNumOut = document.getElementById('oracle-byte-num') as HTMLElement;
  const queryCountOut = document.getElementById('oracle-query-count') as HTMLElement;
  const byteGrid = document.getElementById('oracle-byte-grid') as HTMLElement;
  const recoveredOut = document.getElementById('oracle-recovered-text') as HTMLElement;
  const logEl = document.getElementById('oracle-log') as HTMLElement;

  let attackKey: CryptoKey | null = null;
  let attackIV: Uint8Array | null = null;
  let attackCT: Uint8Array | null = null;
  let isRunning = false;

  setupBtn.addEventListener('click', async () => {
    try {
      const text = plaintextEl.value || 'Attack me!';
      const plain = textToBytes(text);
      const { key, iv, ciphertext } = await setupTarget(plain);

      attackKey = key;
      attackIV = iv;
      attackCT = ciphertext;

      ctOut.textContent = hexEncode(ciphertext);

      // Setup byte grid
      const numBytes = ciphertext.length;
      byteGrid.innerHTML = '';
      for (let i = 0; i < numBytes; i++) {
        const cell = document.createElement('div');
        cell.className = 'oracle-byte';
        cell.textContent = '??';
        cell.setAttribute('aria-label', `Byte ${i}: unknown`);
        cell.id = `oracle-byte-${i}`;
        byteGrid.appendChild(cell);
      }

      progressDiv.hidden = false;
      blockNumOut.textContent = '-';
      byteNumOut.textContent = '-';
      queryCountOut.textContent = '0';
      recoveredOut.textContent = '';
      logEl.innerHTML = '';

      runBtn.disabled = false;
      autoBtn.disabled = false;
    } catch (err) {
      announceError(`Oracle setup failed: ${(err as Error).message}`);
    }
  });

  const callbacks: OracleCallbacks = {
    onByteStart(blockIdx, byteIdx) {
      blockNumOut.textContent = blockIdx.toString();
      byteNumOut.textContent = byteIdx.toString();
      const globalIdx = blockIdx * BLOCK_SIZE + byteIdx;
      const cell = document.getElementById(`oracle-byte-${globalIdx}`);
      if (cell) {
        cell.className = 'oracle-byte active';
        cell.setAttribute('aria-label', `Byte ${globalIdx}: being attacked`);
      }
    },
    onQuery(queryNum, guess, valid) {
      queryCountOut.textContent = queryNum.toString();
      // Log only every 32nd query or valid ones to keep log manageable
      if (valid || queryNum % 32 === 0) {
        const entry = document.createElement('div');
        entry.className = `log-entry ${valid ? 'log-valid' : 'log-invalid'}`;
        entry.textContent = `Query #${queryNum}: guess=0x${guess.toString(16).padStart(2, '0')} → ${valid ? 'VALID ✓' : 'invalid'}`;
        logEl.appendChild(entry);
        logEl.scrollTop = logEl.scrollHeight;
      }
    },
    onByteRecovered(blockIdx, byteIdx, value, char) {
      const globalIdx = blockIdx * BLOCK_SIZE + byteIdx;
      const cell = document.getElementById(`oracle-byte-${globalIdx}`);
      if (cell) {
        cell.className = 'oracle-byte recovered';
        cell.textContent = value.toString(16).padStart(2, '0');
        cell.setAttribute('aria-label', `Byte ${globalIdx}: recovered as 0x${value.toString(16).padStart(2, '0')} (${char})`);
      }
    },
    onBlockComplete(blockIdx, plaintext) {
      const text = bytesToText(plaintext);
      const entry = document.createElement('div');
      entry.className = 'log-entry log-valid';
      entry.textContent = `=== Block ${blockIdx} recovered: "${text}" ===`;
      entry.style.fontWeight = '700';
      logEl.appendChild(entry);
    },
    onComplete(fullPlaintext) {
      const text = bytesToText(fullPlaintext);
      recoveredOut.textContent = text;
      isRunning = false;
      runBtn.disabled = false;
      autoBtn.disabled = false;
      setupBtn.disabled = false;
    },
  };

  async function executeAttack(): Promise<void> {
    if (!attackKey || !attackIV || !attackCT || isRunning) return;
    isRunning = true;
    runBtn.disabled = true;
    autoBtn.disabled = true;
    setupBtn.disabled = true;

    try {
      await runAttack(attackKey, attackIV, attackCT, callbacks);
    } catch (err) {
      isRunning = false;
      runBtn.disabled = false;
      autoBtn.disabled = false;
      setupBtn.disabled = false;
      announceError(`Oracle attack failed: ${(err as Error).message}`);
    }
  }

  runBtn.addEventListener('click', executeAttack);
  autoBtn.addEventListener('click', executeAttack);
}
