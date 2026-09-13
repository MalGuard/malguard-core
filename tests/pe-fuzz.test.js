'use strict';
const assert=require('assert');
const fs=require('fs');
const path=require('path');
const vm=require('vm');
const {webcrypto}=require('crypto');
const ROOT=path.resolve(__dirname,'..');
class FileLike {
  constructor(name, bytes, declaredSize){ this.name=name; this._b=Buffer.from(bytes||''); this.size=declaredSize==null?this._b.length:declaredSize; }
  async arrayBuffer(){ return this._b.buffer.slice(this._b.byteOffset,this._b.byteOffset+this._b.byteLength); }
  slice(s,e){ return new FileLike(this.name,this._b.subarray(s||0,e==null?this._b.length:e)); }
}
function rng(seed){let x=seed>>>0;return()=>{x^=x<<13;x^=x>>>17;x^=x<<5;return x>>>0;};}
function context(){
 const c={console,TextDecoder,TextEncoder,crypto:webcrypto,performance,setTimeout,clearTimeout,AbortController,window:null,
   fetch:async(url)=>String(url)==='rules.json'?new Response(fs.readFileSync(path.join(ROOT,'rules.json')),{status:200,headers:{'content-type':'application/json'}}):new Response('{}',{status:404})};
 c.window=c; vm.createContext(c); vm.runInContext(fs.readFileSync(path.join(ROOT,'engine.js'),'utf8'),c,{filename:'engine.js'}); return c;
}
(async()=>{
 const c=context(); const rand=rng(0x5045465a); let cases=0;
 // malformed size metadata must fail closed before expensive parsing.
 let r=await c.scanFile(new FileLike('bad.asi',Buffer.from('MZ'),NaN));
 assert.notEqual(r.verdict,'safe');
 r=await c.scanFile(new FileLike('bad.asi',Buffer.from('MZ'),Infinity));
 assert.notEqual(r.verdict,'safe');
 // Random PE-shaped inputs. Invalid PE must never emerge SAFE.
 for(let i=0;i<600;i++){
   const len=64+(rand()%8192); const b=Buffer.alloc(len);
   for(let j=0;j<len;j++) b[j]=rand()&255;
   b[0]=0x4d; b[1]=0x5a;
   if(len>=0x40){ const off=rand()%Math.max(1,len+512); b.writeUInt32LE(off>>>0,0x3c); }
   const out=await c.scanFile(new FileLike(i%2?'fuzz.asi':'fuzz.dll',b));
   assert.ok(out && ['safe','suspicious','malicious','invalid'].includes(out.verdict),'invalid engine result shape');
   if(out.peValid!==true) assert.notEqual(out.verdict,'safe','Malformed PE escaped as SAFE');
   cases++;
 }
 console.log(`✓ PE parser adversarial fuzz: ${cases} randomized PE-shaped cases + invalid-size guards passed`);
})().catch(e=>{console.error(e.stack||e);process.exit(1)});
