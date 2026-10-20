// Mutations run only on a committed, clean source baseline. Each is built, killed,
// restored byte-for-byte, rebuilt and tested green before the next begins.
import { readFileSync, writeFileSync, readdirSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..'); process.chdir(root);
const config = process.env.PLAYWRIGHT_CONFIG;
const browser = title => ['npx', ['playwright','test','e2e/claims.spec.ts','--project=chromium','--grep',title,'--workers=1','--retries=0',...(config ? ['--config',config] : [])]];
const unit = ['npx',['vitest','run','src/ofb.test.ts','-t','AES-128 four blocks and every feedback output']];
const build = ['npm',['run','build']];
const run = ([cmd,args]) => spawnSync(cmd,args,{cwd:root,encoding:'utf8',env:{...process.env,CI:'1'}});
const pass = (cmd,label) => { const r=run(cmd); if(r.status!==0) throw Error(`${label}\n${r.stdout}\n${r.stderr}`); return r; };
const hash = () => { const h=createHash('sha256'); const walk=d=>{for(const e of readdirSync(d,{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name))){const p=join(d,e.name); if(e.isDirectory())walk(p);else {h.update(p);h.update(readFileSync(p));}}};walk('dist');return h.digest('hex'); };
const source = 'src/ofb.ts';
const negative = 'OFB gives confidentiality only: a modified ciphertext decrypts without any error, to a plaintext the attacker changed bit for bit.';
const cases = [
 ['ciphertext feedback',source,'return xor(data, await ofbKeystream(key, iv, Math.ceil(data.length / 16)));',`const out = new Uint8Array(data.length); let previous: Uint8Array = iv.slice(); for (let i=0;i<data.length;i+=16) { const y = await ecbEncryptBlock(key, previous); const c = xor(data.slice(i,i+16),y); out.set(c,i); previous=c; } return out;`,unit],
 ['padded final block',source,'const ct = xor(pt, session.stream);','const ct = new Uint8Array(Math.ceil(pt.length / 16) * 16); ct.set(xor(pt, session.stream));',browser('OFB precomputation')],
 ['fresh second IV','src/ofbBroken.ts','const c2 = await ofbXor(key, iv, p2);','const c2 = await ofbXor(key, crypto.getRandomValues(new Uint8Array(16)), p2);',browser('OFB IV reuse')],
 ['calm modified verdict',source,"el('modified').className = 'ofb-alarm';","el('modified').className = 'ofb-output';",browser('OFB negative claim')],
 ['AES counter during XOR',source,'const during = session.counter.calls - before;','session.counter.calls++; const during = session.counter.calls - before;',browser('OFB precomputation')],
 ['missing negative claim',source,negative,'',browser('OFB negative claim')],
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
writeFileSync('mutation-evidence.json',JSON.stringify(evidence,null,2)+'\n');
