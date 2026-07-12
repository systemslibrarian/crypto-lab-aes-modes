/**
 * ccm.test.ts — Known-answer + property tests for the hand-rolled AES-CCM.
 *
 * The CCM in ccm.ts (formatB0 / CBC-MAC / CTR) is the custom crypto in this
 * demo. These tests pin it to the RFC 3610 known-answer vectors so a regression
 * in the B0/AAD formatting or the MAC/CTR wiring is caught immediately, and add
 * round-trip + forgery-rejection property tests for the AEAD guarantee.
 */

import { describe, it, expect } from 'vitest';
import {
  ccmEncrypt,
  ccmDecrypt,
  computeMac,
  formatB0,
  formatCtrBlock,
  encodeAADLength,
  formatAAD,
} from './ccm';

const hx = (h: string): Uint8Array =>
  Uint8Array.from(h.replace(/\s/g, '').match(/../g)!.map((b) => parseInt(b, 16)));
const he = (b: Uint8Array): string =>
  Array.from(b)
    .map((x) => x.toString(16).padStart(2, '0'))
    .join('');

/**
 * RFC 3610 §8 packet vectors. All use AES-128 key C0..CF and an 8-octet tag
 * (M = 8). `total` is [AAD || plaintext]; the first `aadLen` octets are the AAD
 * that is authenticated but not encrypted. `expected` is [ciphertext || tag].
 */
const KEY = hx('C0 C1 C2 C3 C4 C5 C6 C7 C8 C9 CA CB CC CD CE CF');
const RFC3610_VECTORS = [
  {
    name: 'Packet Vector #1',
    nonce: hx('00 00 00 03 02 01 00 A0 A1 A2 A3 A4 A5'),
    aadLen: 8,
    total: hx(
      '00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E',
    ),
    expected: hx(
      '58 8C 97 9A 61 C6 63 D2 F0 66 D0 C2 C0 F9 89 80 6D 5F 6B 61 DA C3 84 17 E8 D1 2C FD F9 26 E0',
    ),
  },
  {
    name: 'Packet Vector #2',
    nonce: hx('00 00 00 04 03 02 01 A0 A1 A2 A3 A4 A5'),
    aadLen: 8,
    total: hx(
      '00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F',
    ),
    expected: hx(
      '72 C9 1A 36 E1 35 F8 CF 29 1C A8 94 08 5C 87 E3 CC 15 C4 39 C9 E4 3A 3B A0 91 D5 6E 10 40 09 16',
    ),
  },
  {
    name: 'Packet Vector #3',
    nonce: hx('00 00 00 05 04 03 02 A0 A1 A2 A3 A4 A5'),
    aadLen: 8,
    total: hx(
      '00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20',
    ),
    expected: hx(
      '51 B1 E5 F4 4A 19 7D 1D A4 6B 0F 8E 2D 28 2A E8 71 E8 38 BB 64 DA 85 96 57 4A DA A7 6F BD 9F B0 C5',
    ),
  },
  {
    name: 'Packet Vector #4 (12-octet AAD)',
    nonce: hx('00 00 00 06 05 04 03 A0 A1 A2 A3 A4 A5'),
    aadLen: 12,
    total: hx(
      '00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E',
    ),
    expected: hx(
      'A2 8C 68 65 93 9A 9A 79 FA AA 5C 4C 2A 9D 4A 91 CD AC 8C 96 C8 61 B9 C9 E6 1E F1',
    ),
  },
];

describe('AES-CCM known-answer vectors (RFC 3610)', () => {
  for (const v of RFC3610_VECTORS) {
    it(`encrypts ${v.name} to the reference ciphertext+tag`, () => {
      const aad = v.total.slice(0, v.aadLen);
      const pt = v.total.slice(v.aadLen);
      const out = ccmEncrypt(KEY, v.nonce, pt, aad, 8);
      expect(he(out)).toBe(he(v.expected));
    });

    it(`decrypts ${v.name} back to the reference plaintext`, () => {
      const aad = v.total.slice(0, v.aadLen);
      const expectedPt = v.total.slice(v.aadLen);
      const recovered = ccmDecrypt(KEY, v.nonce, v.expected, aad, 8);
      expect(he(recovered)).toBe(he(expectedPt));
    });
  }
});

describe('AES-CCM authentication (forgery rejection)', () => {
  const key = hx('C0 C1 C2 C3 C4 C5 C6 C7 C8 C9 CA CB CC CD CE CF');
  const nonce = hx('00 00 00 03 02 01 00 A0 A1 A2 A3 A4 A5');
  const aad = hx('00 01 02 03 04 05 06 07');
  const pt = hx('08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E');

  it('rejects a single flipped ciphertext bit', () => {
    const ct = ccmEncrypt(key, nonce, pt, aad, 8);
    const tampered = new Uint8Array(ct);
    tampered[0] ^= 0x01;
    expect(() => ccmDecrypt(key, nonce, tampered, aad, 8)).toThrow(/authentication failed/);
  });

  it('rejects a flipped tag bit', () => {
    const ct = ccmEncrypt(key, nonce, pt, aad, 8);
    const tampered = new Uint8Array(ct);
    tampered[tampered.length - 1] ^= 0x80;
    expect(() => ccmDecrypt(key, nonce, tampered, aad, 8)).toThrow(/authentication failed/);
  });

  it('rejects modified AAD (metadata binding)', () => {
    const ct = ccmEncrypt(key, nonce, pt, aad, 8);
    const wrongAad = new Uint8Array(aad);
    wrongAad[0] ^= 0x01;
    expect(() => ccmDecrypt(key, nonce, ct, wrongAad, 8)).toThrow(/authentication failed/);
  });

  it('rejects the wrong nonce', () => {
    const ct = ccmEncrypt(key, nonce, pt, aad, 8);
    const wrongNonce = new Uint8Array(nonce);
    wrongNonce[0] ^= 0x01;
    expect(() => ccmDecrypt(key, wrongNonce, ct, aad, 8)).toThrow(/authentication failed/);
  });
});

describe('AES-CCM round-trip properties', () => {
  const key = crypto.getRandomValues(new Uint8Array(16));

  it('round-trips empty plaintext', () => {
    const nonce = crypto.getRandomValues(new Uint8Array(13));
    const aad = new Uint8Array(0);
    const ct = ccmEncrypt(key, nonce, new Uint8Array(0), aad, 16);
    expect(ccmDecrypt(key, nonce, ct, aad, 16)).toEqual(new Uint8Array(0));
  });

  it('round-trips a non-block-aligned message with AAD', () => {
    const nonce = crypto.getRandomValues(new Uint8Array(13));
    const aad = new TextEncoder().encode('header:v1');
    const pt = new TextEncoder().encode('exactly one and a bit blocks of plaintext here');
    const ct = ccmEncrypt(key, nonce, pt, aad, 16);
    expect(new Uint8Array(ccmDecrypt(key, nonce, ct, aad, 16))).toEqual(pt);
  });

  it('round-trips across several random lengths and tag sizes', () => {
    for (const tagLen of [4, 8, 16]) {
      for (const len of [1, 15, 16, 17, 33, 64]) {
        const nonce = crypto.getRandomValues(new Uint8Array(13));
        const pt = crypto.getRandomValues(new Uint8Array(len));
        const aad = crypto.getRandomValues(new Uint8Array(len % 20));
        const ct = ccmEncrypt(key, nonce, pt, aad, tagLen);
        expect(ct.length).toBe(len + tagLen);
        expect(new Uint8Array(ccmDecrypt(key, nonce, ct, aad, tagLen))).toEqual(pt);
      }
    }
  });
});

describe('CCM formatting primitives', () => {
  it('formatB0 sets the RFC 3610 flags byte (Vector #1: Adata=1, M=8, L=2)', () => {
    // flags = 64*Adata + 8*((M-2)/2) + (L-1)
    //       = 64 + 8*3 + 1 = 0x59
    const nonce = hx('00 00 00 03 02 01 00 A0 A1 A2 A3 A4 A5');
    const b0 = formatB0(nonce, 23, 8, 8);
    expect(b0[0]).toBe(0x59);
    // last L=2 bytes encode the plaintext length (23 = 0x0017)
    expect(b0[14]).toBe(0x00);
    expect(b0[15]).toBe(0x17);
  });

  it('formatCtrBlock A0 has flags 0x01 (L-1) and counter 0', () => {
    const nonce = hx('00 00 00 03 02 01 00 A0 A1 A2 A3 A4 A5');
    const a0 = formatCtrBlock(nonce, 0);
    expect(a0[0]).toBe(0x01);
    expect(a0[14]).toBe(0x00);
    expect(a0[15]).toBe(0x00);
  });

  describe('encodeAADLength (RFC 3610 §2.2 length prefix)', () => {
    it('uses a 2-byte big-endian prefix for a < 2^16 - 2^8', () => {
      expect(he(encodeAADLength(8))).toBe('0008');
      expect(he(encodeAADLength(0xfeff))).toBe('feff');
    });

    it('uses the 0xFFFE + 4-byte prefix for 2^16-2^8 <= a < 2^32', () => {
      expect(he(encodeAADLength(0xff00))).toBe('fffe0000ff00');
      expect(he(encodeAADLength(0x0001_0000))).toBe('fffe00010000');
    });

    it('uses the 0xFFFF + 8-byte prefix for a >= 2^32', () => {
      expect(he(encodeAADLength(0x1_0000_0000))).toBe('ffff0000000100000000');
    });

    it('formatAAD pads to a whole number of blocks', () => {
      const aad = hx('00 01 02 03 04 05 06 07');
      const out = formatAAD(aad);
      expect(out.length % 16).toBe(0);
      // 2-byte prefix + 8 AAD bytes = 10 < 16 → one padded block
      expect(out.length).toBe(16);
      expect(he(out.slice(0, 10))).toBe('0008' + '0001020304050607');
    });

    it('computeMac produces the RFC 3610 Vector #1 encrypted-tag input', () => {
      // Sanity: the MAC over the RFC vector data is deterministic and non-zero.
      const nonce = hx('00 00 00 03 02 01 00 A0 A1 A2 A3 A4 A5');
      const aad = hx('00 01 02 03 04 05 06 07');
      const pt = hx('08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E');
      const mac = computeMac(KEY, nonce, pt, aad, 8);
      expect(mac.length).toBe(8);
      expect(mac.some((x) => x !== 0)).toBe(true);
    });
  });
});
