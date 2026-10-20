import { describe, it, expect, vi } from 'vitest';
import { ecb } from '@noble/ciphers/aes.js';
import { ofbKeystream, ofbXor, ofbDecryptBlock, ctrDecryptBlock } from './ofb';
import { ecbEncryptBlock } from './ecb';
import { hexDecode as h, hexEncode } from './ui';
const pt = h('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710');
const iv = h('000102030405060708090a0b0c0d0e0f');
const importKey = (raw: Uint8Array) => crypto.subtle.importKey('raw', raw as BufferSource, 'AES-CBC', true, ['encrypt', 'decrypt']);
// NIST AES_OFB.pdf, AES128 and AES256, all four blocks and intermediate outputs.
// Cross-checked against SP 800-38A F.4.1 and F.4.5, 2026-10-20.
const vectors = [
  { key: '2b7e151628aed2a6abf7158809cf4f3c',
    ct: '3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed8259740051e9c5fecf64344f7a82260edcc304c6528f659c77866a510d9c1d6ae5e',
    stream: '50fe67cc996d32b6da0937e99bafec60d9a4dada0892239f6b8b3d7680e15674a78819583f0308e7a6bf36b1386abf23c6d3416d29165c6fcb8e51a227ba994e', block: '3ad77bb40d7a3660a89ecaf32466ef97' },
  { key: '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
    ct: 'dc7e84bfda79164b7ecd8486985d38604febdc6740d20b3ac88f6ad82a4fb08d71ab47a086e86eedf39d1c5bba97c4080126141d67f37be8538f5a8be740e484',
    stream: 'b7bf3a5df43989dd97f0fa97ebce2f4ae1c656305ed1a7a6563805746fe03edc41635be625b48afc1666dd42a09d96e7f7b93058b8bce0fffea41bf0012cd394', block: 'f3eed1bdb5d2a03c064b5a7e3db181f8' },
];
describe('OFB published vectors through WebCrypto', () => {
  for (const v of vectors) {
    it(`AES-${v.key.length * 4} four blocks and every feedback output`, async () => {
      const key = await importKey(h(v.key));
      expect(hexEncode(await ofbXor(key, iv, pt))).toBe(v.ct);
      expect(hexEncode(await ofbKeystream(key, iv, 4))).toBe(v.stream);
      expect(await ofbXor(key, iv, h(v.ct))).toEqual(pt);
    });
    it(`AES-${v.key.length * 4} derived 60-byte truncation`, async () => {
      expect(hexEncode(await ofbXor(await importKey(h(v.key)), iv, pt.slice(0, 60)))).toBe(v.ct.slice(0, 120));
    });
    it(`AES-${v.key.length * 4} SP 800-38A ECB first block through the exported helper`, async () => {
      expect(hexEncode(await ecbEncryptBlock(await importKey(h(v.key)), pt.slice(0, 16)))).toBe(v.block);
    });
  }
});
it('independent noble ECB chaining agrees for every length 0–200 with random keys and IVs', async () => {
  for (let n = 0; n <= 200; n++) {
    const raw = crypto.getRandomValues(new Uint8Array(n % 2 ? 16 : 32));
    const key = await importKey(raw), initial = crypto.getRandomValues(new Uint8Array(16)), data = crypto.getRandomValues(new Uint8Array(n));
    let feedback: Uint8Array = initial.slice();
    const expected = new Uint8Array(n);
    for (let at = 0; at < n; at += 16) {
      feedback = ecb(raw, { disablePadding: true }).encrypt(feedback);
      for (let j = 0; j < 16 && at + j < n; j++) expected[at + j] = data[at + j] ^ feedback[j];
    }
    expect(await ofbXor(key, initial, data)).toEqual(expected);
  }
});
it('encrypt and decrypt use only forward AES, with a stream independent of plaintext', async () => {
  const spy = vi.spyOn(crypto.subtle, 'decrypt');
  try {
    const key = await importKey(h(vectors[0].key));
    const a = await ofbXor(key, iv, pt), b = await ofbXor(key, iv, new Uint8Array(pt.length));
    expect(a.map((v, i) => v ^ pt[i])).toEqual(b);
    expect(await ofbXor(key, iv, a)).toEqual(pt); expect(spy).not.toHaveBeenCalled();
  } finally { spy.mockRestore(); }
});
it('instrumented random access needs i forward AES calls for OFB and one for CTR', async () => {
  const key = await importKey(h(vectors[0].key));
  const ctrKey = await crypto.subtle.importKey('raw', h(vectors[0].key) as BufferSource, 'AES-CTR', false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CTR', counter: iv as BufferSource, length: 32 }, ctrKey, pt as BufferSource));
  for (let i = 1; i <= 4; i++) {
    const a = { calls: 0 }, b = { calls: 0 };
    expect(await ofbDecryptBlock(key, iv, h(vectors[0].ct), i, a)).toEqual(pt.slice((i - 1) * 16, i * 16));
    expect(await ctrDecryptBlock(key, iv, ct, i, b)).toEqual(pt.slice((i - 1) * 16, i * 16));
    expect(a.calls).toBe(i); expect(b.calls).toBe(1);
  }
});
it('rejects malformed IVs, fractional counts and out-of-range blocks', async () => {
  const key = await importKey(h(vectors[0].key));
  await expect(ofbXor(key, new Uint8Array(15), pt)).rejects.toThrow('16 bytes');
  await expect(ofbKeystream(key, iv, 1.5)).rejects.toThrow('integer');
  for (const i of [0, 5, 1.5]) await expect(ofbDecryptBlock(key, iv, pt, i)).rejects.toThrow('1–4');
});
