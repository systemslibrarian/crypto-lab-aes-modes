// Mutations run only on a committed, clean source baseline. Each is built, killed,
// restored byte-for-byte, rebuilt and tested green before the next begins.
import { readFileSync, writeFileSync, readdirSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..'); process.chdir(root);
const config = process.env.PLAYWRIGHT_CONFIG;
const browser = title => ['npx', ['playwright','test','e2e/cfb.spec.ts','--project=chromium','--grep',title,'--workers=1','--retries=0',...(config ? ['--config',config] : [])]];
const build = ['npm',['run','build']];
const run = ([cmd,args]) => spawnSync(cmd,args,{cwd:root,encoding:'utf8',env:{...process.env,CI:'1'}});
const pass = (cmd,label) => { const r=run(cmd); if(r.status!==0) throw Error(`${label}\n${r.stdout}\n${r.stderr}`); return r; };
const hash = () => { const h=createHash('sha256'); const walk=d=>{for(const e of readdirSync(d,{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name))){const p=join(d,e.name); if(e.isDirectory())walk(p);else {h.update(p);h.update(readFileSync(p));}}};walk('dist');return h.digest('hex'); };
const cases = [
 ["AES output feedback","src/cfb.ts","next.set(segment,16-size);","next.set(stream.slice(0,size),16-size);",['npx',['vitest','run','src/cfb.test.ts','-t',"CFB128 AES128 published vector"]]],
 ["plaintext decryption feedback","src/cfb.ts","const streams=await Promise.all(inputs.map(input=>cfbBlock(key,input,counter)));","const streams:Uint8Array[]=[];let reg:Uint8Array=iv.slice();for(let i=0;i<inputs.length;i++){const st=await cfbBlock(key,reg,counter);streams.push(st);const p=ct.slice(i*size,(i+1)*size).map((b,j)=>b^st[j]);reg=Uint8Array.from([...reg.slice(size),...p]);}",['npx',['vitest','run','src/cfb.test.ts','-t',"CFB128 AES128 published vector"]]],
 ["CFB8 shift by 16 bits","src/cfb.ts","next.set(register.slice(size));","next.set(register.slice(s===8?2:size));",['npx',['vitest','run','src/cfb.test.ts','-t',"CFB8 AES128 published vector"]]],
 ["padded final segment","src/cfb.ts","out=new Uint8Array(data.length)","out=new Uint8Array(Math.ceil(data.length/16)*16)",['npx',['vitest','run','src/cfb.test.ts','-t',"CFB independent noble"]]],
 ["CBC wrong flip block","src/cfbPanel.ts","cb=corrupt(cbc),cbcPlain","cb=cbc.slice(),cbcPlain",browser("CFB comparison strip")],
 ["random zero experiment IV","src/cfbBroken.ts","const iv=new Uint8Array(16);","const iv=crypto.getRandomValues(new Uint8Array(16));",['npx',['vitest','run','src/cfb.test.ts','-t',"CFB zero-IV iff"]]],
 ["CBC-shaped gadget","src/cfbBroken.ts","out[i*16+j]^=known[j]^chosen[j]","out[Math.max(0,i-1)*16+j]^=known[j]^chosen[j]",['npx',['vitest','run','src/cfb.test.ts','-t',"CFB gadget rewrites"]]],
 ["calm gadget verdict","src/cfbPanel.ts","el('gadget-result').className='cfb-alarm';el('gadget-result').dataset.verdict='modified';","el('gadget-result').className='cfb-output';el('gadget-result').dataset.verdict='neutral';",browser("CFB negative claim")],
 ["missing limitation","src/cfbPanel.ts","CFB-128 gives confidentiality only: anyone who knows one plaintext block","This mode has a limitation: someone with a block",browser("CFB negative claim")],
 ["fixture length check broken","src/cfbPanel.ts","['length',plain.length===pt.length]","['length',plain.length!==pt.length]",browser("CFB negative claim")],
];
const dirty=spawnSync('git',['diff','--exit-code','--',...new Set(cases.map(x=>x[1]))],{encoding:'utf8'});
if(dirty.status!==0)throw Error('Commit the source baseline before mutation checks.');
pass(build,'baseline build');const baseline=hash();const evidence=[];
mkdirSync('mutation-logs',{recursive:true});
for(const [name,file,before,after,command] of cases){
 pass(command,`${name}: baseline test`);
 const original=readFileSync(file,'utf8');if(original.split(before).length!==2)throw Error(`${name}: expected one mutation site`);
 let mutant;
 try{
  writeFileSync(file,original.replace(before,after));
  const diff=spawnSync('git',['diff','--',file],{encoding:'utf8'}).stdout;if(!diff.trim())throw Error(`${name}: empty diff`);
  pass(build,`${name}: mutant build`); mutant=hash();if(mutant===baseline)throw Error(`${name}: bundle did not move`);
  const r=run(command);writeFileSync(`mutation-logs/${name.replaceAll(' ','-')}.log`,r.stdout+r.stderr);
  if(r.status===0 || !/expect\(|AssertionError|Error: expect/.test(r.stdout+r.stderr))throw Error(`${name}: no assertion kill\n${r.stdout}\n${r.stderr}`);
  evidence.push({name,sourceDiff:diff,baseline,mutant,namedTest:command[1].includes('--grep') ? command[1][command[1].indexOf('--grep')+1] : command[1].at(-1),assertionFailure:true,retries:0});
 }finally{writeFileSync(file,original);pass(build,`${name}: restore build`);if(hash()!==baseline)throw Error(`${name}: restored hash differs`);pass(command,`${name}: restored test`);}
 evidence.at(-1).restoredGreen=true;console.log(`${name}: killed; exact artifact restored; owning test green`);
}
writeFileSync('mutation-evidence-cfb.json',JSON.stringify(evidence,null,2)+'\n');
