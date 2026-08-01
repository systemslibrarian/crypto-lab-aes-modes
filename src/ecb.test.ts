/**
 * ecb.test.ts — Known-answer + property tests for the ECB exhibit.
 *
 * The ECB panel encrypts with WebCrypto (AES-CBC / zero IV per block) and
 * decrypts with @noble/ciphers ECB, then relies on analyzeBlocks() to surface
 * the "identical plaintext blocks → identical ciphertext blocks" leak that is
 * the whole point of the exhibit. These tests:
 *   1. pin the raw AES block permutation to the FIPS 197 (2001) Appendix C.1
 *      and NIST SP 800-38A Appendix F.1.1 KATs, and
 *   2. verify analyzeBlocks() actually detects (and does not fabricate) the
 *      duplicate-block structure the UI advertises.
 */

import { describe, it, expect } from 'vitest';
import { ecb } from '@noble/ciphers/aes';
import { analyzeBlocks } from './ecb';

const hx = (h: string): Uint8Array =>
  Uint8Array.from(h.replace(/\s/g, '').match(/../g)!.map((b) => parseInt(b, 16)));
const he = (b: Uint8Array): string =>
  Array.from(b)
    .map((x) => x.toString(16).padStart(2, '0'))
    .join('');

describe('AES single-block permutation (known-answer vectors)', () => {
  // Cited precisely: this is the AES-128 vector from Appendix C.1 of the
  // ORIGINAL FIPS 197 (2001). It is not the Appendix B "Cipher Example", which
  // uses key 2b7e1516..3c and input 3243f6a8..34, and it is no longer in
  // Appendix C at all — FIPS 197-upd1 (May 2023) replaced the example-vector
  // appendix with a pointer to the NIST CSRC example-values page.
  it('matches the FIPS 197 (2001) Appendix C.1 AES-128 vector', () => {
    const key = hx('000102030405060708090a0b0c0d0e0f');
    const pt = hx('00112233445566778899aabbccddeeff');
    const ct = ecb(key, { disablePadding: true }).encrypt(pt);
    expect(he(ct)).toBe('69c4e0d86a7b0430d8cdb78070b4c55a');
  });

  it('matches NIST SP 800-38A F.1.1 ECB-AES128 (all four blocks)', () => {
    const key = hx('2b7e151628aed2a6abf7158809cf4f3c');
    const vectors: [string, string][] = [
      ['6bc1bee22e409f96e93d7e117393172a', '3ad77bb40d7a3660a89ecaf32466ef97'],
      ['ae2d8a571e03ac9c9eb76fac45af8e51', 'f5d3d58503b9699de785895a96fdbaaf'],
      ['30c81c46a35ce411e5fbc1191a0a52ef', '43b1cd7f598ece23881b00e3ed030688'],
      ['f69f2445df4f9b17ad2b417be66c3710', '7b0c785e27e8ad3f8223207104725dd4'],
    ];
    for (const [p, c] of vectors) {
      // @noble/ciphers cipher instances are single-use, so build one per block.
      expect(he(ecb(key, { disablePadding: true }).encrypt(hx(p)))).toBe(c);
    }
  });

  it('round-trips encrypt→decrypt for a random key/plaintext', () => {
    const key = crypto.getRandomValues(new Uint8Array(16));
    const pt = crypto.getRandomValues(new Uint8Array(48));
    const ct = ecb(key, { disablePadding: true }).encrypt(pt);
    const back = ecb(key, { disablePadding: true }).decrypt(ct);
    expect(new Uint8Array(back)).toEqual(pt);
  });
});

describe('analyzeBlocks (ECB structure-leak detection)', () => {
  it('flags repeated ciphertext blocks as duplicates', () => {
    // Two identical 16-byte blocks + one distinct block.
    const b0 = '00112233445566778899aabbccddeeff';
    const b1 = 'ffeeddccbbaa99887766554433221100';
    const ct = hx(b0 + b0 + b1);
    const { blocks, duplicates } = analyzeBlocks(ct);
    expect(blocks.length).toBe(3);
    // b0 appears at positions 0 and 1; b1 is unique.
    expect(duplicates.size).toBe(1);
    expect(duplicates.get(b0)).toEqual([0, 1]);
    expect(duplicates.has(b1)).toBe(false);
  });

  it('reports no duplicates when every block differs', () => {
    const ct = hx(
      '00112233445566778899aabbccddeeff' +
        'ffeeddccbbaa99887766554433221100' +
        '0102030405060708090a0b0c0d0e0f10',
    );
    const { blocks, duplicates } = analyzeBlocks(ct);
    expect(blocks.length).toBe(3);
    expect(duplicates.size).toBe(0);
  });

  it('detects three-way repetition (all positions recorded)', () => {
    const b = 'a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1';
    const ct = hx(b + b + b);
    const { duplicates } = analyzeBlocks(ct);
    expect(duplicates.get(b)).toEqual([0, 1, 2]);
  });
});
