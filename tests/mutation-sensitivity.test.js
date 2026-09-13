'use strict';
const assert=require('assert');
const fs=require('fs');
const path=require('path');
const vm=require('vm');
const {webcrypto}=require('crypto');
const ROOT=path.resolve(__dirname,'..');
class F{constructor(n,b){this.name=n;this._b=Buffer.from(b);this.size=this._b.length}async arrayBuffer(){return this._b.buffer.slice(this._b.byteOffset,this._b.byteOffset+this._b.byteLength)}slice(s,e){return new F(this.name,this._b.subarray(s||0,e==null?this._b.length:e))}}
function analyzerFrom(source){const c={console,TextDecoder,TextEncoder,crypto:webcrypto,performance,window:null};c.window=c;vm.createContext(c);vm.runInContext(source,c,{filename:'script-analyzer.js'});return c.ScriptAnalyzer;}
(async()=>{
 const source=fs.readFileSync(path.join(ROOT,'script-analyzer.js'),'utf8');
 const target="return { score, verdict, confidence, fired, categories };";
 assert.ok(source.includes(target),'mutation target changed; update mutation test intentionally');
 const mutant=source.replace(target,"return { score: 100, verdict: 'safe', confidence: 'low', fired: [], categories: new Set() };");
 const baseline=analyzerFrom(source), mutated=analyzerFrom(mutant);
 const payload=fs.readFileSync(path.join(ROOT,'tests','corpus','malicious-synthetic-credential-exfil.cs'));
 const normal=await baseline.analyze(new F('malicious-synthetic-credential-exfil.cs',payload));
 const bad=await mutated.analyze(new F('malicious-synthetic-credential-exfil.cs',payload));
 assert.notEqual(normal.verdict,'safe','baseline high-risk sentinel unexpectedly SAFE');
 assert.equal(bad.verdict,'safe','forced-SAFE mutant did not change observable behavior');
 assert.notEqual(bad.verdict,normal.verdict,'mutation survived high-risk sentinel');
 console.log(`✓ Mutation sensitivity: forced-SAFE ScriptAnalyzer scoring mutant killed (baseline=${normal.verdict}, mutant=${bad.verdict})`);
})().catch(e=>{console.error(e.stack||e);process.exit(1)});
