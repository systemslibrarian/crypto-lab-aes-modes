/**
 * forbidden.test.ts — GF(2^128) arithmetic + the GCM forbidden-attack forgery.
 *
 * Two layers of teeth:
 *   1. Pin the GHASH field arithmetic to the published GCM Test Case 2
 *      (McGrew & Viega, "The Galois/Counter Mode of Operation", 2005) — if the
 *      GF(2^128) multiplication is off by a bit, the reconstructed tag won't
 *      match the standard's fixed answer.
 *   2. Drive the end-to-end attack: recover H, forge a (ciphertext, tag), and
 *      require REAL WebCrypto AES-GCM to accept it on nonce reuse and REJECT it
 *      when the nonce is fresh.
 */

import { describe, it, expect } from 'vitest';
import {
  gfmul,
  gfadd,
  gfsqrt,
  gfinv,
  ghash,
  recoverH,
  recoverS,
  forgeTag,
  runForbiddenAttack,
} from './forbidden';

const hx = (h: string): Uint8Array =>
  Uint8Array.from(h.replace(/\s/g, '').match(/../g)!.map((b) => parseInt(b, 16)));
const he = (b: Uint8Array): string =>
  Array.from(b)
    .map((x) => x.toString(16).padStart(2, '0'))
    .join('');

// E_K(block) via WebCrypto AES-CTR with the block itself as the counter and a
// zero plaintext: CTR output = E_K(counter) ⊕ 0 = E_K(counter). Lets us obtain
// the raw AES permutation without an ECB primitive.
async function aesEncryptBlock(keyHex: string, blockHex: string): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    'raw',
    hx(keyHex) as BufferSource,
    { name: 'AES-CTR' },
    false,
    ['encrypt'],
  );
  const out = await crypto.subtle.encrypt(
    { name: 'AES-CTR', counter: hx(blockHex) as BufferSource, length: 32 },
    key,
    new Uint8Array(16),
  );
  return new Uint8Array(out);
}

describe('GF(2^128) arithmetic (GCM convention)', () => {
  it('inverse and square root are consistent: (a⁻¹)·a = 1, (√a)² = a', () => {
    const a = hx('0388dace60b6a392f328c2b971b2fe78');
    const one = hx('80000000000000000000000000000000'); // GF(2^128) identity in GCM order
    expect(he(gfmul(a, gfinv(a)))).toBe(he(one));
    const r = gfsqrt(a);
    expect(he(gfmul(r, r))).toBe(he(a));
  });

  it('reconstructs the tag of GCM Test Case 2 from H and C (published KAT)', async () => {
    // McGrew & Viega Test Case 2: K = 0^128, IV = 0^96, one zero plaintext block.
    const H = await aesEncryptBlock(
      '00000000000000000000000000000000',
      '00000000000000000000000000000000',
    );
    expect(he(H)).toBe('66e94bd4ef8a2c3b884cfa59ca342b2e'); // fixed subkey from the paper

    const C = hx('0388dace60b6a392f328c2b971b2fe78'); // ciphertext block from the paper
    // J0 = IV || 0^31 || 1 for a 96-bit IV; S = E_K(J0).
    const S = await aesEncryptBlock(
      '00000000000000000000000000000000',
      '00000000000000000000000000000001',
    );
    const tag = gfadd(ghash(H, new Uint8Array(0), C), S);
    expect(he(tag)).toBe('ab6e47d42cec13bdf53a67b21257bddf'); // fixed tag from the paper
  });
});

describe('forbidden attack: H recovery from two single-block tags', () => {
  it('recovers the H that E_K would have used, self-consistently', async () => {
    // Build two messages under a known H/S and confirm recoverH inverts it.
    const H = hx('66e94bd4ef8a2c3b884cfa59ca342b2e');
    const S = hx('58e2fccefa7e3061367f1d57a4e7455a');
    const c1 = hx('0388dace60b6a392f328c2b971b2fe78');
    const c2 = hx('ffeeddccbbaa998877665544332211ff');
    const t1 = gfadd(ghash(H, new Uint8Array(0), c1), S);
    const t2 = gfadd(ghash(H, new Uint8Array(0), c2), S);
    const rec = recoverH(c1, t1, c2, t2);
    expect(rec).not.toBeNull();
    expect(he(rec!)).toBe(he(H));
    expect(he(recoverS(H, c1, t1))).toBe(he(S));
    // Forged tag for a third ciphertext matches a from-scratch GHASH+S tag.
    const c3 = hx('1122334455667788990011223344abcd');
    expect(he(forgeTag(H, S, c3))).toBe(he(gfadd(ghash(H, new Uint8Array(0), c3), S)));
  });

  it('returns null when the two ciphertexts are identical (non-invertible)', () => {
    const c = hx('0388dace60b6a392f328c2b971b2fe78');
    const t = hx('ab6e47d42cec13bdf53a67b21257bddf');
    expect(recoverH(c, t, c, t)).toBeNull();
  });
});

describe('end-to-end forgery against the real WebCrypto AES-GCM verifier', () => {
  it('nonce REUSE ⇒ forged (ciphertext, tag) is ACCEPTED and decrypts to chosen text', async () => {
    const r = await runForbiddenAttack('PAY BOB $10.00!!', 'HELLO SECOND MSG', 'PAY EVE $10000!!', true);
    expect(r.accepted).toBe(true);
    expect(r.recoveredPlaintext).toBe('PAY EVE $10000!!');
  });

  it('fresh nonce (control) ⇒ forged tag is REJECTED by WebCrypto', async () => {
    const r = await runForbiddenAttack('PAY BOB $10.00!!', 'HELLO SECOND MSG', 'PAY EVE $10000!!', false);
    expect(r.accepted).toBe(false);
    expect(r.recoveredPlaintext).toBeNull();
  });
});
