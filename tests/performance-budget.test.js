'use strict';
const assert=require('assert');
const fs=require('fs');
const path=require('path');
const vm=require('vm');
const {webcrypto}=require('crypto');
const ROOT=path.resolve(__dirname,'..');
class F{constructor(n,b){this.name=n;this._b=Buffer.from(b);this.size=this._b.length}async arrayBuffer(){return this._b.buffer.slice(this._b.byteOffset,this._b.byteOffset+this._b.byteLength)}slice(s,e){return new F(this.name,this._b.subarray(s||0,e==null?this._b.length:e))}}
const c={console,TextDecoder,TextEncoder,crypto:webcrypto,performance,setTimeout,clearTimeout,window:null};c.window=c;vm.createContext(c);vm.runInContext(fs.readFileSync(path.join(ROOT,'script-analyzer.js'),'utf8'),c);
(async()=>{
 const payload=('local x=1; print(x)\n').repeat(50000); // ~1 MB benign source
 const f=new F('large-benign.lua',payload);
 const t=performance.now(); const r=await c.ScriptAnalyzer.analyze(f); const ms=performance.now()-t;
 assert.notEqual(r.verdict,'malicious');
 assert.notEqual(r.errorCode,'analysis_timeout','1MB benign corpus exceeded analyzer budget');
 assert.ok(ms<5000,`Performance regression: ${ms.toFixed(1)}ms`);
 console.log(`✓ Performance budget: 1MB-class Lua analyzed in ${ms.toFixed(1)}ms without timeout/malicious FP`);
})().catch(e=>{console.error(e.stack||e);process.exit(1)});
