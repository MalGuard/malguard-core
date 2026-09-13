'use strict';
const assert=require('assert'); const fs=require('fs'); const path=require('path'); const vm=require('vm'); const {webcrypto}=require('crypto');
const ROOT=path.resolve(__dirname,'..');
function load(c,n){vm.runInContext(fs.readFileSync(path.join(ROOT,n),'utf8'),c,{filename:n});}
function makeContext(){
 const c={console,TextDecoder,TextEncoder,crypto:webcrypto,performance,setTimeout,clearTimeout,AbortController,ReadableStream,DecompressionStream,Blob,Response,window:null}; c.window=c;
 c.fetch=async(url)=>String(url)==='rules.json'?new Response(fs.readFileSync(path.join(ROOT,'rules.json')),{status:200,headers:{'content-type':'application/json'}}):new Response('{}',{status:404});
 vm.createContext(c);
 for(const n of ['malguard-contract.js','engine.js','multilayer.js','gta-mod-detector.js','archive-inspector.js','archive-entry-reader.js','script-analyzer.js','app.js']) load(c,n);
 c.MalGuardWorkerScanner={version:'1.2.0',isSupported:()=>true,warmup:async()=>({ready:true,protocol:2,resultSchemaVersion:'1.0.0'})};
 load(c,'self-test.js'); return c;
}
(async()=>{
 let c=makeContext(); let r=await c.MalGuardSelfTest.run(); assert.equal(r.ok,true,JSON.stringify(r.checks)); assert.ok(r.checks.length>=8);
 c=makeContext(); const original=c.ScriptAnalyzer.analyze; c.ScriptAnalyzer.analyze=async()=>({supported:true,verdict:'safe',errorCode:null});
 r=await c.MalGuardSelfTest.run(); assert.equal(r.ok,false,'self-test must fail when a live component violates a fail-closed control');
 assert.ok(r.checks.some(x=>x.id==='script-binary-fail-closed'&&!x.ok)); c.ScriptAnalyzer.analyze=original;
 console.log('✓ Self-Test integrity: live component probes execute and a weakened analyzer cannot hard-code PASS');
})().catch(e=>{console.error(e.stack||e);process.exit(1)});
