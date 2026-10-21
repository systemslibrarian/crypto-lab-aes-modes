import type { EvaluationCounter } from './ofb';
import { ecbEncryptBlock } from './ecb';
import { hexEncode } from './ui';
export type Segment = 8 | 128;
export async function cfbBlock(key: CryptoKey, input: Uint8Array, counter?: EvaluationCounter): Promise<Uint8Array> {
  if(counter)counter.calls++;
  const out=await ecbEncryptBlock(key,input);counter?.trace?.push({input:hexEncode(input),output:hexEncode(out)});return out;
}
function validate(iv: Uint8Array,s: Segment){if(iv.length!==16)throw Error(`IV must be 16 bytes; found ${iv.length}.`);if(s!==8&&s!==128)throw Error('Only CFB-8 and CFB-128 are implemented.');}
export async function cfbEncrypt(key:CryptoKey,iv:Uint8Array,data:Uint8Array,s:Segment=128,counter?:EvaluationCounter):Promise<Uint8Array>{
 validate(iv,s);const size=s/8,out=new Uint8Array(data.length);let register:Uint8Array=iv.slice();
 for(let i=0;i<data.length;i+=size){const stream=await cfbBlock(key,register,counter),length=Math.min(size,data.length-i),segment=new Uint8Array(length);for(let j=0;j<length;j++)segment[j]=data[i+j]^stream[j];out.set(segment,i);
  if(length===size){const next=new Uint8Array(16);next.set(register.slice(size));next.set(segment,16-size);register=next;}
 }return out;
}
export function cfbDecryptInputs(iv:Uint8Array,ct:Uint8Array,s:Segment):Uint8Array[]{validate(iv,s);const size=s/8,joined=new Uint8Array(16+ct.length);joined.set(iv);joined.set(ct,16);return Array.from({length:Math.ceil(ct.length/size)},(_,i)=>joined.slice(i*size,i*size+16));}
export async function cfbDecrypt(key:CryptoKey,iv:Uint8Array,ct:Uint8Array,s:Segment=128,counter?:EvaluationCounter):Promise<Uint8Array>{
 validate(iv,s);const size=s/8,out=new Uint8Array(ct.length),inputs=cfbDecryptInputs(iv,ct,s);
 // Every AES input is already available from the received ciphertext. No AES inverse is used.
 const streams=await Promise.all(inputs.map(input=>cfbBlock(key,input,counter)));
 for(let i=0;i<ct.length;i++)out[i]=ct[i]^streams[Math.floor(i/size)][i%size];return out;
}
export {mountCFBPanel} from './cfbPanel';
// [extension] point: CFB-1 requires bit-level segment handling and its own published vectors.
