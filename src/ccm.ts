/**
 * ccm.ts — CCM mode implementation
 *
 * WebCrypto does not support AES-CCM. This demo implements CCM (RFC 3610,
 * NIST SP 800-38C) using AES block primitives from @noble/ciphers.
 *
 * CCM = CBC-MAC (authentication) + CTR (encryption).
 * Two-pass construction: first compute CBC-MAC over formatted input,
 * then encrypt plaintext with CTR starting at counter=1,
 * and encrypt the tag with counter=0.
 */

import { ecb } from '@noble/ciphers/aes';
import { hexEncode, textToBytes, announceError } from './ui';

const BLOCK = 16;

/**
 * Encrypt a single AES block using @noble/ciphers ecb.
 */
function aesBlock(key: Uint8Array, block: Uint8Array): Uint8Array {
  const cipher = ecb(key, { disablePadding: true });
  return cipher.encrypt(block);
}

function xorBlocks(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(BLOCK);
  for (let i = 0; i < BLOCK; i++) {
    out[i] = a[i] ^ (b[i] ?? 0);
  }
  return out;
}

/**
 * Format the CCM B_0 block per RFC 3610 §2.2.
 * Flags = 8*Adata + 8*((t-2)/2) + (q-1)
 * where t = tag length in bytes, q = length field size = 15 - nonce.length
 */
function formatB0(
  nonce: Uint8Array,
  plaintextLen: number,
  aadLen: number,
  tagLen: number
): Uint8Array {
  const q = 15 - nonce.length; // length field size
  const flags =
    (aadLen > 0 ? 0x40 : 0) |
    (((tagLen - 2) / 2) << 3) |
    (q - 1);

  const b0 = new Uint8Array(BLOCK);
  b0[0] = flags;
  b0.set(nonce, 1);

  // Encode plaintext length in last q bytes (big-endian)
  let len = plaintextLen;
  for (let i = BLOCK - 1; i >= BLOCK - q; i--) {
    b0[i] = len & 0xff;
    len >>>= 8;
  }

  return b0;
}

/**
 * Format AAD blocks per RFC 3610 §2.2.
 * If 0 < aadLen < 2^16–2^8, encode as 2-byte length prefix.
 */
function formatAAD(aad: Uint8Array): Uint8Array {
  if (aad.length === 0) return new Uint8Array(0);

  // 2-byte length prefix + AAD + padding to block boundary
  const encoded = new Uint8Array(2 + aad.length);
  encoded[0] = (aad.length >> 8) & 0xff;
  encoded[1] = aad.length & 0xff;
  encoded.set(aad, 2);

  // Pad to block boundary
  const padded = new Uint8Array(Math.ceil(encoded.length / BLOCK) * BLOCK);
  padded.set(encoded);
  return padded;
}

/**
 * Format CTR counter block per RFC 3610 §2.3.
 * A_i: flags=q-1, nonce, counter (q bytes big-endian)
 */
function formatCtrBlock(nonce: Uint8Array, counter: number): Uint8Array {
  const q = 15 - nonce.length;
  const a = new Uint8Array(BLOCK);
  a[0] = q - 1; // flags for CTR
  a.set(nonce, 1);

  let c = counter;
  for (let i = BLOCK - 1; i >= BLOCK - q; i--) {
    a[i] = c & 0xff;
    c >>>= 8;
  }
  return a;
}

/**
 * CCM encrypt per RFC 3610.
 * Returns ciphertext || tag.
 */
function ccmEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
  tagLen: number = 16
): Uint8Array {
  // 1. CBC-MAC: compute authentication tag T
  const b0 = formatB0(nonce, plaintext.length, aad.length, tagLen);
  let mac = aesBlock(key, b0);

  // Process AAD blocks
  const aadBlocks = formatAAD(aad);
  for (let i = 0; i < aadBlocks.length; i += BLOCK) {
    const block = aadBlocks.slice(i, i + BLOCK);
    mac = aesBlock(key, xorBlocks(mac, block));
  }

  // Process plaintext blocks
  for (let i = 0; i < plaintext.length; i += BLOCK) {
    const block = new Uint8Array(BLOCK);
    const end = Math.min(i + BLOCK, plaintext.length);
    block.set(plaintext.slice(i, end));
    mac = aesBlock(key, xorBlocks(mac, block));
  }

  // T = first tagLen bytes of final MAC
  const T = mac.slice(0, tagLen);

  // 2. CTR encryption
  // Encrypt tag with counter=0
  const S0 = aesBlock(key, formatCtrBlock(nonce, 0));
  const encTag = new Uint8Array(tagLen);
  for (let i = 0; i < tagLen; i++) {
    encTag[i] = T[i] ^ S0[i];
  }

  // Encrypt plaintext with counter=1,2,...
  const ciphertext = new Uint8Array(plaintext.length);
  const numBlocks = Math.ceil(plaintext.length / BLOCK);
  for (let i = 0; i < numBlocks; i++) {
    const Si = aesBlock(key, formatCtrBlock(nonce, i + 1));
    const offset = i * BLOCK;
    const end = Math.min(offset + BLOCK, plaintext.length);
    for (let j = offset; j < end; j++) {
      ciphertext[j] = plaintext[j] ^ Si[j - offset];
    }
  }

  // Output: ciphertext || encrypted tag
  const output = new Uint8Array(ciphertext.length + tagLen);
  output.set(ciphertext);
  output.set(encTag, ciphertext.length);
  return output;
}

export function mountCCMPanel(): void {
  const plaintextEl = document.getElementById('ccm-plaintext') as HTMLTextAreaElement;
  const aadEl = document.getElementById('ccm-aad') as HTMLInputElement;
  const encryptBtn = document.getElementById('ccm-encrypt-btn') as HTMLButtonElement;
  const keyOut = document.getElementById('ccm-key') as HTMLElement;
  const nonceOut = document.getElementById('ccm-nonce') as HTMLElement;
  const ctOut = document.getElementById('ccm-ciphertext') as HTMLElement;

  encryptBtn.addEventListener('click', () => {
    try {
      // AES-128-CCM: 16-byte key, 13-byte nonce (common per RFC 3610)
      const key = crypto.getRandomValues(new Uint8Array(16));
      const nonce = crypto.getRandomValues(new Uint8Array(13));
      const plaintext = textToBytes(plaintextEl.value || 'CCM for constrained environments.');
      const aad = textToBytes(aadEl.value || '');

      const result = ccmEncrypt(key, nonce, plaintext, aad, 16);

      keyOut.textContent = hexEncode(key);
      nonceOut.textContent = hexEncode(nonce);
      ctOut.textContent = hexEncode(result);
    } catch (err) {
      announceError(`CCM encryption failed: ${(err as Error).message}`);
    }
  });
}
