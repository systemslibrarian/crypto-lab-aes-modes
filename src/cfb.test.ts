import {it,expect,vi} from 'vitest';
import {cfb,ecb} from '@noble/ciphers/aes.js';
import {cfbEncrypt,cfbDecrypt} from './cfb';
import {reuseCFB,zeroIvSearch,gadget} from './cfbBroken';
const h=(s:string)=>Uint8Array.from(s.match(/../g)!.map(x=>parseInt(x,16))),hex=(a:Uint8Array)=>Buffer.from(a).toString('hex');
const key128=h('2b7e151628aed2a6abf7158809cf4f3c'),key256=h('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4');
const iv=h('000102030405060708090a0b0c0d0e0f'),pt=h('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710');
const key=(k=key128)=>crypto.subtle.importKey('raw',k,'AES-CBC',true,['encrypt','decrypt']);
// NIST SP 800-38A Appendix F.3 and CSRC AES_CFB.pdf, CFB128 and first 16 CFB8 bytes.
for(const [bits,k,c128,c8]of [[128,key128,'3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6','3b79424c9c0dd436bace9e0ed4586a4f'],[256,key256,'dc7e84bfda79164b7ecd8486985d386039ffed143b28b1c832113c6331e5407bdf10132415e54b92a13ed0a8267ae2f975a385741ab9cef82031623d55b1e471','dc1f1a8520a64db55fcc8ac554844e88']] as const){
 it(`CFB128 AES${bits} published vector and decryption`,async()=>{const ck=await key(k);expect(hex(await cfbEncrypt(ck,iv,pt,128))).toBe(c128);expect(await cfbDecrypt(ck,iv,h(c128),128)).toEqual(pt);});
 it(`CFB8 AES${bits} published vector and decryption`,async()=>{const ck=await key(k);expect(hex(await cfbEncrypt(ck,iv,pt.slice(0,16),8))).toBe(c8);expect(await cfbDecrypt(ck,iv,h(c8),8)).toEqual(pt.slice(0,16));});
}
it('CFB AES outputs derived by XOR from the published ciphertext',async()=>{const c={calls:0,trace:[] as {input:string;output:string}[]};await cfbEncrypt(await key(),iv,pt,128,c);expect(c.trace.map(t=>t.output)).toEqual(['50fe67cc996d32b6da0937e99bafec60','668bcf60beb005a35354a201dab36bda','16bd032100975551547b4de89daea630','36d42170a312871947ef8714799bc5f6']);expect(c.calls).toBe(4);});
let seed=12345;const random=(n:number)=>Uint8Array.from({length:n},()=>{seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;return seed&255;});
it('CFB independent noble CFB128 and byte-shift ECB reference at lengths 0–200',async()=>{for(let n=0;n<=200;n++){const raw=random(n%2?16:32),v=random(16),p=random(n),k=await key(raw),ciphertext=await cfbEncrypt(k,v,p,128);expect(ciphertext).toEqual(cfb(raw,v).encrypt(p));expect(await cfbDecrypt(k,v,ciphertext,128)).toEqual(p);let r=v.slice();const ref=new Uint8Array(n);for(let i=0;i<n;i++){ref[i]=p[i]^ecb(raw,{disablePadding:true}).encrypt(r)[0];r=Uint8Array.from([...r.slice(1),ref[i]]);}expect(await cfbEncrypt(k,v,p,8)).toEqual(ref);expect(await cfbDecrypt(k,v,ref,8)).toEqual(p);}},20000);
it('CFB neither direction calls subtle.decrypt',async()=>{const spy=vi.spyOn(crypto.subtle,'decrypt');try{const k=await key();await cfbDecrypt(k,iv,await cfbEncrypt(k,iv,pt,128),128);expect(spy).not.toHaveBeenCalled();}finally{spy.mockRestore();}});
for (const s of [128, 8] as const) {
  it(`CFB encryption feedback is ciphertext and depends on plaintext at s=${s}`, async () => {
    const k = await key(), altered = pt.slice();
    altered[0] ^= 1;
    const traces: { input: string; output: string }[][] = [];
    for (const plaintext of [pt, altered]) {
      const counter = { calls: 0, trace: [] as { input: string; output: string }[] };
      const ciphertext = await cfbEncrypt(k, iv, plaintext, s, counter);
      // SP 800-38A: I_1 = LSB_(128-s)(IV) || C_0, independently of decryption helpers.
      const expected = s === 128
        ? ciphertext.slice(0, 16)
        : Uint8Array.from([...iv.slice(1), ciphertext[0]]);
      expect(counter.trace[0].input).toBe(hex(iv));
      expect(counter.trace[1].input).toBe(hex(expected));
      traces.push(counter.trace);
    }
    expect(traces[1][1].input).not.toBe(traces[0][1].input);
  });
}
it('CFB bit flip and last-block flip have exact local and following-block damage',async()=>{const k=await key(),c=await cfbEncrypt(k,iv,pt);for(const i of [0,48]){const x=c.slice();x[i]^=8;const p=await cfbDecrypt(k,iv,x);expect(p[i]^pt[i]).toBe(8);expect(p.slice(i+1,i+16)).toEqual(pt.slice(i+1,i+16));if(i+16<pt.length)expect(p.slice(i+16,i+32)).not.toEqual(pt.slice(i+16,i+32));expect(p.slice(i+32)).toEqual(pt.slice(i+32));}});
it('CFB8 deletion damage is a subset of the next 16 received positions',async()=>{const k=await key(),c=await cfbEncrypt(k,iv,pt,8);for(const pos of [0,7,58]){const removed=Uint8Array.from([...c.slice(0,pos),...c.slice(pos+1)]),expected=Uint8Array.from([...pt.slice(0,pos),...pt.slice(pos+1)]),p=await cfbDecrypt(k,iv,removed,8);for(let i=0;i<p.length;i++)if(p[i]!==expected[i])expect(i>=pos&&i<pos+16).toBe(true);}});
it('CFB128 whole block deletion heals; one byte does not restore alignment',async()=>{const k=await key(),c=await cfbEncrypt(k,iv,pt);expect((await cfbDecrypt(k,iv,c.slice(16),128)).slice(16)).toEqual(pt.slice(32));expect((await cfbDecrypt(k,iv,c.slice(1),128)).slice(32)).not.toEqual(pt.slice(33));});
it('CFB IV reuse leaks through the first differing block only',async()=>{const p2=pt.slice();p2[20]^=3;const r=await reuseCFB(await key(),iv,pt,p2);expect(r.leak).toBe(32);expect(r.recovered).toEqual(p2.slice(0,32));expect(r.c1.slice(32).map((v,i)=>v^r.c2[32+i])).not.toEqual(pt.slice(32).map((v,i)=>v^p2[32+i]));});
it('CFB zero-IV iff over 2000 seeded keys is nonvacuous and uses the search IV',async()=>{let hits=0;for(let i=0;i<2000;i++){const raw=random(16),expected=ecb(raw,{disablePadding:true}).encrypt(new Uint8Array(16))[0]===0,r=await zeroIvSearch(1,()=>{},{keyAt:()=>raw});expect(r.kind==='hit').toBe(expected);if(r.kind==='hit'){hits++;expect([...r.ciphertext]).toEqual(Array(8).fill(0));expect([...r.iv]).toEqual(Array(16).fill(0));}}expect(hits).toBeGreaterThan(0);},20000);
it('CFB no hit exhausts all 4096 keys', async () => {
  const fixedKey = key128;
  expect(ecb(fixedKey, { disablePadding: true }).encrypt(new Uint8Array(16))[0]).not.toBe(0);
  const result = await zeroIvSearch(4096, () => {}, { keyAt: () => fixedKey });
  expect(result.kind).toBe('no-hit');
  expect(result.tried).toBe(4096);
});
it('CFB search rejects caps outside 0–4096', async () => {
  await expect(zeroIvSearch(4097, () => {})).rejects.toThrow('Search cap');
  await expect(zeroIvSearch(-1, () => {})).rejects.toThrow('Search cap');
});
it('CFB pre-aborted search is cancelled before trying a key', async () => {
  const ac = new AbortController();
  ac.abort();
  const result = await zeroIvSearch(8, () => {}, { signal: ac.signal });
  expect(result.kind).toBe('cancelled');
  expect(result.tried).toBe(0);
});
it('CFB gadget rewrites chosen block and only garbles the following block',async()=>{const k=await key(),c=await cfbEncrypt(k,iv,pt),chosen=random(16),p=await cfbDecrypt(k,iv,gadget(c,1,pt.slice(16,32),chosen));expect(p.slice(16,32)).toEqual(chosen);expect(p.slice(32,48)).not.toEqual(pt.slice(32,48));expect(p.slice(0,16)).toEqual(pt.slice(0,16));expect(p.slice(48)).toEqual(pt.slice(48));});
it('CFB wrong known block does not produce chosen plaintext',async()=>{const k=await key(),c=await cfbEncrypt(k,iv,pt),chosen=random(16),known=pt.slice(0,16);known[0]^=1;const p=await cfbDecrypt(k,iv,gadget(c,0,known,chosen));expect(p[0]).toBe(chosen[0]^1);});
it('CFB wrong block length fails closed',()=>expect(()=>gadget(pt,0,new Uint8Array(15),new Uint8Array(16))).toThrow('16 bytes'));
it('CFB bad IV length fails closed',async()=>{await expect(cfbEncrypt(await key(),new Uint8Array(15),pt)).rejects.toThrow('IV must be 16');});
it('CFB empty plaintext has exactly empty ciphertext',async()=>expect((await cfbEncrypt(await key(),iv,new Uint8Array())).length).toBe(0));
