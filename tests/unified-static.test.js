'use strict';
const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { UnifiedScanPipeline, unifiedResult } = require('../desktop-app/unified-scan-pipeline');
const { MalwareBazaarClient } = require('../desktop-app/threat-intel/malwarebazaar-client');
const HASH = 'a'.repeat(64);
const delay = ms => new Promise(r => setTimeout(r, ms));
async function finished(p, id) {
  for (let n=0;n<500;n++) { const s=p.snapshot(id); if (['completed','failed','cancelled'].includes(s.state)) return s; await delay(10); }
  throw new Error('session did not finish');
}
const payload = data => ({ ok:true, status:200, text:async()=>JSON.stringify(data) });
const client = fetchImpl => new MalwareBazaarClient({ authKeyProvider:async()=> 'synthetic-secret', fetchImpl, timeoutMs:250, maxResponseBytes:1024 });

test('all legacy models receive the same non-executing pipeline; misses never approve', async()=>{
  const calls=[];
  const p=new UnifiedScanPipeline({scanner:{scanPath:async(file,mode)=>{calls.push(mode);return {finalVerdict:'safe', sourceIdentity:{revalidated:true}, threatIntel:{status:'not_found'}};}}});
  for(const model of ['unified','standard','plus','pro']) {
    const s=await finished(p,p.start('/fixture.lua',model,{allowCloudFallback:true,allowAiEvidence:true}).id);
    assert.equal(s.model,'unified'); assert.equal(s.finalResult.verdict,'inconclusive');
    assert.equal(s.finalResult.fileBytesShared,false); assert.equal(s.finalResult.sampleExecutionStarted,false);
    assert.equal(s.finalResult.fusion.safeClaim.allowed,false);
  }
  assert.deepEqual(calls,['pro','pro','pro','pro']);
});
test('known detections retained; offline/partial/error states never approve',()=>{
  for(const verdict of ['malicious','suspicious']) assert.equal(unifiedResult({finalVerdict:verdict}).verdict,verdict);
  for(const status of ['not_found','unavailable','not_configured','disabled','auth_error']) {
    assert.notEqual(unifiedResult({finalVerdict:'safe', threatIntel:{status}}).verdict,'safe');
  }
  assert.equal(unifiedResult({finalVerdict:'inconclusive',threatIntel:{status:'known_malicious'}}).verdict,'malicious');
});
test('cancellation retains capacity until actual cleanup and cannot publish a late verdict',async()=>{
  let release, cleaned=false;
  const p=new UnifiedScanPipeline({maxActive:1, scanner:{scanPath:()=>new Promise(r=>{release=r;})}});
  const id=p.start('/fixture.lua','unified',{onFinish:async()=>{await delay(20);cleaned=true;}}).id;
  await delay(0); assert.equal(p.cancel(id).state,'cancelling');
  assert.throws(()=>p.start('/another.lua'),{code:'TOO_MANY_LOCAL_SCANS'});
  release({finalVerdict:'safe'});
  const s=await finished(p,id); assert.equal(s.state,'cancelled'); assert(cleaned); assert.notEqual(s.finalResult.verdict,'safe');
  assert.equal(p.cancel('missing'),null);
});
test('cleanup failures and scanner exceptions fail closed without exception text leakage',async()=>{
  for(const scenario of ['scanner','cleanup']) {
    const p=new UnifiedScanPipeline({scanner:{scanPath:async()=>{if(scenario==='scanner')throw new Error('synthetic-secret');return {finalVerdict:'safe'};}}});
    const s=await finished(p,p.start('/fixture.lua','unified',{onFinish:()=>{if(scenario==='cleanup')throw new Error('synthetic-secret');}}).id);
    assert.equal(s.state,'failed'); assert.equal(s.finalResult.verdict,'inconclusive');assert(!JSON.stringify(s).includes('synthetic-secret'));
  }
});
test('MalwareBazaar requires exact non-empty response hash',async()=>{
  for(const row of [{},{sha256_hash:'wrong'},{sha256_hash:'b'.repeat(64)}]) {
    const r=await client(async()=>payload({query_status:'ok',data:[row]})).lookupSha256(HASH);
    assert.equal(r.status,'unavailable');assert.equal(r.reason,'hash_mismatch');
  }
});
test('MalwareBazaar deadline covers a stalled body, bounded stream rejects oversized data',async()=>{
  const start=Date.now();
  const stalled=await client(async()=>({ok:true,text:()=>new Promise(()=>{})})).lookupSha256(HASH);
  assert.equal(stalled.reason,'timeout'); assert(Date.now()-start<1500);
  let cancelled=false;
  const stream=new ReadableStream({pull(c){c.enqueue(new Uint8Array(1025));},cancel(){cancelled=true;}});
  const oversized=await client(async()=>new Response(stream)).lookupSha256(HASH);
  assert.equal(oversized.reason,'response_too_large'); assert(cancelled);
});
test('MalwareBazaar rate limit, network failure, malformed JSON and redirect policy',async()=>{
  assert.equal((await client(async()=>({ok:false,status:429})).lookupSha256(HASH)).reason,'rate_limited');
  const r=await client(async()=>{throw new Error('synthetic-secret');}).lookupSha256(HASH);
  assert.equal(r.reason,'network_error'); assert(!JSON.stringify(r).includes('synthetic-secret'));
  assert.equal((await client(async()=>({ok:true,text:async()=>'{'})).lookupSha256(HASH)).reason,'invalid_json');
  await client(async(_,o)=>{assert.equal(o.redirect,'error');assert.equal(new URLSearchParams(o.body).get('query'),'get_info');return payload({query_status:'hash_not_found'});}).lookupSha256(HASH);
});
test('real localhost API: one model, no sandbox, malformed requests, aliases, benign upload and cleanup',async()=>{
  const temp=await fs.mkdtemp(path.join(os.tmpdir(),'mg-unified-'));
  const previous=process.env.LOCALAPPDATA;process.env.LOCALAPPDATA=temp;
  const {startServer}=require('../desktop-app/server');
  const server=await startServer(0);const base=`http://127.0.0.1:${server.address().port}`;
  const post=(url,body)=>fetch(base+url,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
  try {
    const status=await (await fetch(base+'/api/status')).json();assert.deepEqual(status.supportedModels,['unified']);assert.equal(status.sandboxMode,'disabled');
    for(const route of ['status','analyze','self-test','readiness']) {
      const r=await post('/api/sandbox/'+route,{path:'/fixture.exe'});assert.equal(r.status,410);
    }
    assert.equal((await post('/api/model-scan/start',{path:'x',model:'invalid'})).status,400);
    assert.equal((await post('/api/model-scan/start',{})).status,400);
    const headers={'x-malguard-local-upload':'1','content-type':'application/octet-stream'};
    const r=await fetch(base+'/api/model-scan/upload?name=fixture.lua',{method:'POST',headers,body:'-- benign test only\nlocal value = 1'});
    assert.equal(r.status,202);const id=(await r.json()).session.id;
    let s;
    for(let i=0;i<1500;i++){s=(await (await fetch(base+'/api/model-scan/status?id='+id)).json()).session;if(['completed','failed'].includes(s.state))break;await delay(100);}
    assert.equal(s.state,'completed');assert.equal(s.model,'unified');assert.equal(s.finalResult.verdict,'inconclusive');
    const files=await fs.readdir(temp,{recursive:true});assert(!files.some(x=>x.endsWith('fixture.lua')));
    const bad=await fetch(base+'/api/model-scan/upload?name=..%2Fbad',{method:'POST',headers,body:'bad'});assert.equal(bad.status,400);
    const missing=await post('/api/model-scan/start',{path:path.join(temp,'absent.lua')});const missingId=(await missing.json()).session.id;
    for(let i=0;i<100;i++){s=(await (await fetch(base+'/api/model-scan/status?id='+missingId)).json()).session;if(s.state==='failed')break;await delay(100);}
    assert.equal(s.state,'failed');assert.equal(s.finalResult.verdict,'inconclusive');
  } finally {await new Promise(r=>server.close(r));if(previous===undefined)delete process.env.LOCALAPPDATA;else process.env.LOCALAPPDATA=previous;await fs.rm(temp,{recursive:true,force:true});}
});
