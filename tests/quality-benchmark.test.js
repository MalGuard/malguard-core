'use strict';
const assert=require('assert');
const fs=require('fs');
const path=require('path');
const vm=require('vm');
const {webcrypto}=require('crypto');
const ROOT=path.resolve(__dirname,'..'), CORPUS=path.join(__dirname,'corpus');
class F{constructor(n,b){this.name=n;this._b=Buffer.from(b);this.size=this._b.length}async arrayBuffer(){return this._b.buffer.slice(this._b.byteOffset,this._b.byteOffset+this._b.byteLength)}slice(s,e){return new F(this.name,this._b.subarray(s||0,e==null?this._b.length:e))}}
const c={console,TextDecoder,TextEncoder,crypto:webcrypto,performance,setTimeout,clearTimeout,window:null};c.window=c;vm.createContext(c);vm.runInContext(fs.readFileSync(path.join(ROOT,'script-analyzer.js'),'utf8'),c);
(async()=>{
 const manifest=JSON.parse(fs.readFileSync(path.join(CORPUS,'manifest.json'),'utf8'));
 const benign=manifest.filter(x=>x.file.startsWith('benign-'));
 const risky=manifest.filter(x=>x.file.startsWith('suspicious-')||x.file.startsWith('malicious-'));
 let benignMalicious=0, benignSuspicious=0, riskySafe=0;
 for(const t of benign){const r=await c.ScriptAnalyzer.analyze(new F(t.file,fs.readFileSync(path.join(CORPUS,t.file)))); if(r.verdict==='malicious')benignMalicious++; if(r.verdict==='suspicious')benignSuspicious++;}
 for(const t of risky){const r=await c.ScriptAnalyzer.analyze(new F(t.file,fs.readFileSync(path.join(CORPUS,t.file)))); if(r.verdict==='safe')riskySafe++;}
 assert.equal(benignMalicious,0,'Benign corpus produced MALICIOUS false positives');
 assert.ok(benignSuspicious/Math.max(1,benign.length)<=0.25,`Suspicious rate on benign corpus too high: ${benignSuspicious}/${benign.length}`);
 assert.equal(riskySafe,0,'Risk-labeled regression cases escaped as SAFE');
 console.log(`✓ Quality benchmark: benign malicious FP 0/${benign.length}, benign suspicious ${benignSuspicious}/${benign.length}, risky SAFE escapes 0/${risky.length}`);
})().catch(e=>{console.error(e.stack||e);process.exit(1)});
