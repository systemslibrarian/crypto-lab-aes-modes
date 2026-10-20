/** Deliberately broken: two messages reuse one key/IV. Only the attack control calls this. */
import { ofbXor } from './ofb';
import { xor } from './helpers';
export async function reuseOFB(key: CryptoKey, iv: Uint8Array, p1: Uint8Array, p2: Uint8Array) {
  const c1 = await ofbXor(key, iv, p1);
  const c2 = await ofbXor(key, iv, p2);
  return { c1, c2, recovered: xor(xor(c1, c2), p1) };
}
