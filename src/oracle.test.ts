import { afterEach, expect, it, vi } from 'vitest';
import * as ui from './ui';
import { paddingOracle, runAttack, setupTarget, type OracleCallbacks } from './oracle';

afterEach(() => vi.restoreAllMocks());

function callbacks(): OracleCallbacks {
  return {
    onByteStart: vi.fn(), onQuery: vi.fn(), onByteRecovered: vi.fn(),
    onBlockComplete: vi.fn(), onComplete: vi.fn(),
  };
}

it('rejects a zero-padding decrypt success, preserving full-block padding', async () => {
  const key = {} as CryptoKey;
  const iv = new Uint8Array(16);
  const ciphertext = new Uint8Array(16);
  const decrypt = vi.spyOn(ui, 'aesDecrypt');
  // The observed WebKit behavior: no bytes removed from a block ending in 0.
  decrypt.mockResolvedValueOnce(new ArrayBuffer(16));
  expect(await paddingOracle(key, iv, ciphertext)).toBe(false);
  // PKCS#7 allows 16 bytes of padding on an empty message.
  decrypt.mockResolvedValueOnce(new ArrayBuffer(0));
  expect(await paddingOracle(key, iv, ciphertext)).toBe(true);
});

it('recognizes valid padding and rejects an invalid suffix with real AES-CBC', async () => {
  const { key, iv, ciphertext } = await setupTarget(new TextEncoder().encode('Attack me!'));
  expect(await paddingOracle(key, iv, ciphertext)).toBe(true);
  // The final block has six 0x06 padding bytes. Changing only the last to
  // 0x02 leaves a mismatching previous byte and must be rejected.
  const bad = new Uint8Array(iv);
  bad[15] ^= 6 ^ 2;
  expect(await paddingOracle(key, bad, ciphertext)).toBe(false);
  const zero = new Uint8Array(iv);
  zero[15] ^= 6;
  expect(await paddingOracle(key, zero, ciphertext)).toBe(false);
});

it.each(['Attack me!', 'ABCDEFGHIJKLMNOP', 'CBC across more than one block!'])
  ('recovers real plaintext: %s', async (text) => {
    const target = await setupTarget(new TextEncoder().encode(text));
    const cb = callbacks();
    const result = await runAttack(target.key, target.iv, target.ciphertext, cb);
    expect(new TextDecoder().decode(result.plaintext)).toBe(text);
    expect(cb.onByteRecovered).toHaveBeenCalledTimes(target.ciphertext.length);
    expect(cb.onComplete).toHaveBeenCalledOnce();
  });

it('stops without fabricated bytes or a completion when no guess is valid', async () => {
  vi.spyOn(ui, 'aesDecrypt').mockRejectedValue(new Error('invalid padding'));
  const cb = callbacks();
  await expect(runAttack({} as CryptoKey, new Uint8Array(16), new Uint8Array(16), cb))
    .rejects.toThrow('No valid padding response for block 0, byte 15');
  expect(cb.onQuery).toHaveBeenCalledTimes(256);
  expect(cb.onByteRecovered).not.toHaveBeenCalled();
  expect(cb.onComplete).not.toHaveBeenCalled();
});
