/** Deliberately broken experiments are separate from the guarded normal-encryption UI. */
import {cfbEncrypt,cfbBlock} from './cfb';
import {xor} from './helpers';
import type {EvaluationCounter} from './ofb';
export async function reuseCFB(key:CryptoKey,iv:Uint8Array,p1:Uint8Array,p2:Uint8Array){
 const c1=await cfbEncrypt(key,iv,p1,128),c2=await cfbEncrypt(key,iv,p2,128),overlap=Math.min(p1.length,p2.length);let leak=overlap;
 for(let i=0;i<overlap;i++)if(p1[i]!==p2[i]){leak=Math.min(overlap,(Math.floor(i/16)+1)*16);break;}
 return {c1,c2,leak,recovered:xor(p1.slice(0,leak),xor(c1.slice(0,leak),c2.slice(0,leak)))};
}
export async function zeroIvSearch(cap:number,onProgress:(tried:number)=>void,options:{signal?:AbortSignal;keyAt?:(i:number)=>Uint8Array}={}){
 if(!Number.isInteger(cap)||cap<0||cap>4096)throw Error('Search cap must be 0–4096 keys.');const counter:EvaluationCounter={calls:0};
 const iv=new Uint8Array(16);
 for(let i=0;i<cap;i++){
  if(options.signal?.aborted)return {kind:'cancelled' as const,tried:i,calls:counter.calls};
  const raw=options.keyAt?.(i)??crypto.getRandomValues(new Uint8Array(16));const key=await crypto.subtle.importKey('raw',raw as BufferSource,'AES-CBC',true,['encrypt']);
  const stream=await cfbBlock(key,iv,counter);onProgress(i+1);
  if(stream[0]===0){const ciphertext=await cfbEncrypt(key,iv,new Uint8Array(8),8,counter);return {kind:'hit' as const,tried:i+1,calls:counter.calls,raw,iv,stream,ciphertext};}
  if(i%16===15)await new Promise(resolve=>setTimeout(resolve,0));
 }return {kind:'no-hit' as const,tried:cap,calls:counter.calls};
}
export function gadget(ct:Uint8Array,i:number,known:Uint8Array,chosen:Uint8Array){
 if(known.length!==16||chosen.length!==16)throw Error(`Known and chosen blocks must each be 16 bytes; found ${known.length} and ${chosen.length}.`);
 if(!Number.isInteger(i)||i<0||(i+1)*16>ct.length)throw Error('Choose a complete ciphertext block.');const out=ct.slice();for(let j=0;j<16;j++)out[i*16+j]^=known[j]^chosen[j];return out;
}
