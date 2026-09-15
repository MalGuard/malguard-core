'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { webcrypto } = require('crypto');
const ROOT = path.resolve(__dirname, '..');
const FIX = path.join(__dirname, 'fixtures', 'gtav-benign-scripts.zip');

class FileLike {
  constructor(name, bytes) { this.name=name; this._b=Buffer.from(bytes||''); this.size=this._b.length; }
  async arrayBuffer(){ return this._b.buffer.slice(this._b.byteOffset,this._b.byteOffset+this._b.byteLength); }
  slice(s,e){ return new FileLike(this.name,this._b.subarray(s||0,e==null?this._b.length:e)); }
}
function ctx(){ const c={console,TextDecoder,TextEncoder,crypto:webcrypto,performance,setTimeout,clearTimeout,ReadableStream,DecompressionStream,window:null}; c.window=c; vm.createContext(c); return c; }
function load(c,n){ vm.runInContext(fs.readFileSync(path.join(ROOT,n),'utf8'),c,{filename:n}); }
function rng(seed){ let x=seed>>>0; return ()=>{ x^=x<<13; x^=x>>>17; x^=x<<5; return x>>>0; }; }

(async()=>{
  const c=ctx(); load(c,'gta-mod-detector.js'); load(c,'archive-inspector.js'); load(c,'archive-entry-reader.js'); load(c,'script-analyzer.js');
  const allowed = new Set(['safe','suspicious','malicious','inconclusive','invalid']);
  const rand=rng(0x4d474831);
  let randomCases=0, mutatedCases=0;

  for(let i=0;i<500;i++){
    const len=rand()%2048;
    const b=Buffer.alloc(len); for(let j=0;j<len;j++) b[j]=rand()&255;
    const sr=await c.ScriptAnalyzer.analyze(new FileLike(i%2?'fuzz.lua':'fuzz.cs',b));
    assert.ok(sr && allowed.has(sr.verdict), 'ScriptAnalyzer returned invalid shape');
    const ar=await c.ArchiveInspector.inspect(new FileLike('fuzz.zip',b));
    assert.ok(ar && typeof ar.inspectionStatus==='string', 'ArchiveInspector returned invalid shape');
    randomCases++;
  }

  const original=fs.readFileSync(FIX);
  for(let i=0;i<500;i++){
    const b=Buffer.from(original);
    const flips=1+(rand()%4);
    for(let f=0;f<flips;f++){ const pos=rand()%b.length; b[pos]^=(1<<(rand()%8)); }
    const file=new FileLike('mutated.zip',b);
    const inspection=await c.ArchiveInspector.inspect(file);
    assert.ok(inspection && typeof inspection.inspectionStatus==='string');
    const ds=Array.isArray(inspection.scriptTargetDescriptors)?inspection.scriptTargetDescriptors:[];
    if(ds.length){
      const rr=await c.ArchiveEntryReader.readEntry(file,ds[0]);
      assert.ok(rr && typeof rr.ok==='boolean', 'Reader must fail closed structurally');
    }
    mutatedCases++;
  }

  console.log(`✓ Malformed/fuzz resilience: ${randomCases} random + ${mutatedCases} mutated ZIP cases completed without uncaught parser failure`);
})().catch(e=>{ console.error(e.stack||e); process.exit(1); });
