/**
 * forbidden.ts — GCM "forbidden attack" (Joux, 2006): nonce-reuse forgery.
 *
 * When an AES-GCM nonce repeats under the same key, the encrypted counter-0
 * block S = E_K(J0) is identical across both messages, so it cancels when the
 * two authentication tags are added (XORed) in GF(2^128). What remains is a
 * polynomial equation in the GHASH subkey H — and H is the *authentication
 * key*. Recover it and you can compute a valid tag for any ciphertext of your
 * choosing under that (key, nonce). This module recovers H for real and forges
 * a (ciphertext, tag) pair that the browser's own WebCrypto AES-GCM verifier
 * accepts.
 *
 * SCALE / SIMPLIFICATION (labelled honestly on the page):
 *   Both captured messages are exactly ONE AES block (16 bytes) with empty AAD.
 *   Equal length ⇒ the GHASH length block L and the term L·H are identical
 *   across the two messages, so they cancel along with S:
 *
 *       T1 ⊕ T2 = (C1 ⊕ C2) · H²          (all other terms cancel)
 *       H²      = (T1 ⊕ T2) · (C1 ⊕ C2)⁻¹
 *       H       = √(H²)                    (unique square root in GF(2^128))
 *
 *   This gives a UNIQUE H with no candidate-root search — the cleanest honest
 *   form of the attack. The general multi-block attack yields a set of
 *   candidate roots that must be sieved against the oracle; the recovered H is
 *   just as real, so we use the single-block form for clarity. Everything below
 *   is computed in the real GCM field; nothing is hardcoded. The proof of
 *   correctness is that real WebCrypto AES-GCM accepts the forged tag.
 */

// ─── GF(2^128) arithmetic in the GCM bit convention ───
//
// GCM's field is GF(2)[x]/(x^128 + x^7 + x^2 + x + 1), with the "bit-reflected"
// byte/bit ordering fixed by NIST SP 800-38D: within the 16-byte block the
// left-most bit is the lowest-degree coefficient. The right-shift multiplier
// with reduction constant 0xE1 (= 11100001b) below is the reference algorithm.

const BLOCK = 16;

export function gfadd(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(BLOCK);
  for (let i = 0; i < BLOCK; i++) out[i] = a[i] ^ b[i];
  return out;
}

export function gfmul(x: Uint8Array, y: Uint8Array): Uint8Array {
  const z = new Uint8Array(BLOCK);
  const v = new Uint8Array(y);
  for (let i = 0; i < 128; i++) {
    // Bit i of x, MSB-first: byte i>>3, bit (7 - (i & 7)).
    if ((x[i >> 3] >> (7 - (i & 7))) & 1) {
      for (let j = 0; j < BLOCK; j++) z[j] ^= v[j];
    }
    // v = v >> 1 over the whole 128-bit big-endian value; if the bit shifted
    // out of the LSB was 1, reduce by XORing 0xE1 into the top byte.
    const lsb = v[BLOCK - 1] & 1;
    for (let j = BLOCK - 1; j > 0; j--) {
      v[j] = (v[j] >> 1) | ((v[j - 1] & 1) << 7);
    }
    v[0] >>= 1;
    if (lsb) v[0] ^= 0xe1;
  }
  return z;
}

export function gfsqr(a: Uint8Array): Uint8Array {
  return gfmul(a, a);
}

/** Multiplicative inverse via Fermat: a^(2^128 − 2). */
export function gfinv(a: Uint8Array): Uint8Array {
  // a^(2^128 − 2) = a^2 · a^4 · a^8 · … · a^(2^127)  (Itoh–Tsujii-style chain).
  let result: Uint8Array | null = null;
  let power: Uint8Array = new Uint8Array(a); // a^(2^0)
  for (let i = 1; i < 128; i++) {
    power = gfsqr(power); // now a^(2^i)
    result = result === null ? power : gfmul(result, power);
  }
  // result = product_{i=1..127} a^(2^i) = a^(2^128 − 2).
  return result as Uint8Array;
}

/** Unique square root in GF(2^m): √a = a^(2^(m−1)), i.e. 127 squarings. */
export function gfsqrt(a: Uint8Array): Uint8Array {
  let r: Uint8Array = new Uint8Array(a);
  for (let i = 0; i < 127; i++) r = gfsqr(r);
  return r;
}

/** GHASH length block: 64-bit bit-lengths of AAD and ciphertext, big-endian. */
export function lengthBlock(aadBytes: number, ctBytes: number): Uint8Array {
  const L = new Uint8Array(BLOCK);
  const dv = new DataView(L.buffer);
  dv.setBigUint64(0, BigInt(aadBytes) * 8n, false);
  dv.setBigUint64(8, BigInt(ctBytes) * 8n, false);
  return L;
}

/** GHASH_H over AAD then ciphertext then the length block (blocks zero-padded). */
export function ghash(H: Uint8Array, aad: Uint8Array, ct: Uint8Array): Uint8Array {
  let x: Uint8Array = new Uint8Array(BLOCK);
  const feed = (data: Uint8Array): void => {
    for (let off = 0; off < data.length; off += BLOCK) {
      const block = new Uint8Array(BLOCK);
      block.set(data.subarray(off, Math.min(off + BLOCK, data.length)));
      x = gfmul(gfadd(x, block), H);
    }
  };
  feed(aad);
  feed(ct);
  x = gfmul(gfadd(x, lengthBlock(aad.length, ct.length)), H);
  return x;
}

/**
 * Recover the GHASH subkey H from two single-block, equal-length, empty-AAD
 * messages that reused a nonce. Returns null if the ciphertexts are equal
 * (C1 ⊕ C2 = 0 is not invertible — happens only if the plaintexts matched).
 */
export function recoverH(
  c1: Uint8Array,
  t1: Uint8Array,
  c2: Uint8Array,
  t2: Uint8Array,
): Uint8Array | null {
  const den = gfadd(c1, c2);
  if (den.every((b) => b === 0)) return null;
  const h2 = gfmul(gfadd(t1, t2), gfinv(den));
  return gfsqrt(h2);
}

/** Recover S = E_K(J0) once H is known, from one (ciphertext, tag) pair. */
export function recoverS(H: Uint8Array, c1: Uint8Array, t1: Uint8Array): Uint8Array {
  return gfadd(t1, ghash(H, new Uint8Array(0), c1));
}

/** Forge a tag for an arbitrary ciphertext under the recovered (H, S). */
export function forgeTag(H: Uint8Array, S: Uint8Array, ctStar: Uint8Array): Uint8Array {
  return gfadd(ghash(H, new Uint8Array(0), ctStar), S);
}

// ─── UI wiring ───

import { hexEncode, textToBytes, bytesToText, announceError, aesEncrypt } from './ui';

function escapeHtml(s: string): string {
  const div = document.createElement('div');
  div.textContent = s;
  return div.innerHTML;
}

/** Pad/truncate a UTF-8 string to exactly 16 bytes so both captures are one block. */
function toBlock(text: string, fallback: string): Uint8Array {
  const raw = textToBytes(text.length ? text : fallback);
  const block = new Uint8Array(BLOCK);
  block.set(raw.subarray(0, BLOCK));
  return block;
}

interface AttackResult {
  H: Uint8Array;
  S: Uint8Array;
  c1: Uint8Array;
  t1: Uint8Array;
  c2: Uint8Array;
  t2: Uint8Array;
  forgedCt: Uint8Array;
  forgedTag: Uint8Array;
  accepted: boolean;
  recoveredPlaintext: string | null;
  error: string | null;
}

/**
 * Run the full attack against a freshly generated key. `reuseNonce` controls
 * whether message 2 reuses message 1's nonce (the vulnerability) or gets a
 * fresh one (the control). The forged tag is verified against REAL WebCrypto
 * AES-GCM decrypt — `accepted` reflects whether the browser's verifier let it
 * through.
 */
export async function runForbiddenAttack(
  p1Text: string,
  p2Text: string,
  forgedText: string,
  reuseNonce: boolean,
): Promise<AttackResult> {
  const key = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  );

  const nonce1 = crypto.getRandomValues(new Uint8Array(12));
  const nonce2 = reuseNonce ? nonce1 : crypto.getRandomValues(new Uint8Array(12));

  const p1 = toBlock(p1Text, 'PAY BOB $10.00!!');
  const p2 = toBlock(p2Text, 'HELLO SECOND MSG');

  const enc = async (nonce: Uint8Array, pt: Uint8Array) => {
    const combined = new Uint8Array(
      await aesEncrypt({ name: 'AES-GCM', iv: nonce, tagLength: 128 }, key, pt),
    );
    return { ct: new Uint8Array(combined.subarray(0, BLOCK)), tag: new Uint8Array(combined.subarray(BLOCK)) };
  };

  const m1 = await enc(nonce1, p1);
  const m2 = await enc(nonce2, p2);

  // Recover H from the two tags (uses nonce1's data as if both shared it — the
  // attacker only ever sees ciphertext+tag, never the nonce relationship).
  const H = recoverH(m1.ct, m1.tag, m2.ct, m2.tag) ?? new Uint8Array(BLOCK);
  const S = recoverS(H, m1.ct, m1.tag);

  // Chosen-plaintext forgery: keystream is P1 ⊕ C1 (known because we know P1).
  // Craft a ciphertext that decrypts to the attacker's chosen message.
  const keystream = gfadd(p1, m1.ct);
  const forgedPt = toBlock(forgedText, 'PAY EVE $10000!!');
  const forgedCt = gfadd(forgedPt, keystream);
  const forgedTag = forgeTag(H, S, forgedCt);

  // Verify against the REAL WebCrypto AES-GCM verifier, under nonce1.
  const forgedCombined = new Uint8Array(BLOCK * 2);
  forgedCombined.set(forgedCt, 0);
  forgedCombined.set(forgedTag, BLOCK);

  let accepted = false;
  let recoveredPlaintext: string | null = null;
  let error: string | null = null;
  try {
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce1, tagLength: 128 },
      key,
      forgedCombined as BufferSource,
    );
    accepted = true;
    recoveredPlaintext = bytesToText(new Uint8Array(pt));
  } catch (e) {
    accepted = false;
    error = (e as Error).name || 'verification failed';
  }

  return {
    H,
    S,
    c1: m1.ct,
    t1: m1.tag,
    c2: m2.ct,
    t2: m2.tag,
    forgedCt,
    forgedTag,
    accepted,
    recoveredPlaintext,
    error,
  };
}

export function mountForbiddenPanel(): void {
  const p1El = document.getElementById('forbidden-p1') as HTMLInputElement | null;
  const p2El = document.getElementById('forbidden-p2') as HTMLInputElement | null;
  const forgeEl = document.getElementById('forbidden-forged') as HTMLInputElement | null;
  const runBtn = document.getElementById('forbidden-run-btn') as HTMLButtonElement | null;
  const controlBtn = document.getElementById('forbidden-control-btn') as HTMLButtonElement | null;
  const out = document.getElementById('forbidden-output') as HTMLElement | null;
  if (!runBtn || !controlBtn || !out) return;

  const render = (r: AttackResult, reuseNonce: boolean): void => {
    const rows = `
      <div class="hex-row"><span class="hex-label">Captured C₁ / T₁</span><code>${hexEncode(r.c1)}</code> · <code>${hexEncode(r.t1)}</code></div>
      <div class="hex-row"><span class="hex-label">Captured C₂ / T₂</span><code>${hexEncode(r.c2)}</code> · <code>${hexEncode(r.t2)}</code></div>
      <div class="hex-row"><span class="hex-label">Recovered H (GHASH subkey)</span><code>${hexEncode(r.H)}</code></div>
      <div class="hex-row"><span class="hex-label">Recovered S = E<sub>K</sub>(J₀)</span><code>${hexEncode(r.S)}</code></div>
      <div class="hex-row"><span class="hex-label">Forged ciphertext</span><code>${hexEncode(r.forgedCt)}</code></div>
      <div class="hex-row"><span class="hex-label">Forged tag</span><code>${hexEncode(r.forgedTag)}</code></div>`;

    if (r.accepted) {
      out.innerHTML = `
        ${rows}
        <p class="decrypt-takeaway decrypt-fail" data-verdict="accepted">
          ⚠ WebCrypto AES-GCM <strong>ACCEPTED the forgery</strong> — it returned:
          <code>${escapeHtml(r.recoveredPlaintext ?? '')}</code>.
          The recovered H is the real authentication key. No genuine tag was ever
          computed by the key owner for this message; the browser's own verifier
          could not tell.
        </p>`;
    } else {
      out.innerHTML = `
        ${rows}
        <p class="decrypt-takeaway decrypt-ok" data-verdict="rejected">
          ✓ WebCrypto AES-GCM <strong>REJECTED the forgery</strong> (${escapeHtml(r.error ?? '')}).
          ${reuseNonce
            ? 'Unexpected — the nonce was reused, so the attack should have succeeded.'
            : 'The nonce was NOT reused: S differs between the two messages, so it never cancels, the recovered “H” is wrong, and the forged tag fails. This is the control — the attack only works on nonce reuse.'}
        </p>`;
    }
    out.hidden = false;
  };

  runBtn.addEventListener('click', async () => {
    try {
      const r = await runForbiddenAttack(
        p1El?.value ?? '',
        p2El?.value ?? '',
        forgeEl?.value ?? '',
        true,
      );
      render(r, true);
    } catch (e) {
      announceError(`Forbidden attack failed: ${(e as Error).message}`);
    }
  });

  controlBtn.addEventListener('click', async () => {
    try {
      const r = await runForbiddenAttack(
        p1El?.value ?? '',
        p2El?.value ?? '',
        forgeEl?.value ?? '',
        false,
      );
      render(r, false);
    } catch (e) {
      announceError(`Control run failed: ${(e as Error).message}`);
    }
  });
}
