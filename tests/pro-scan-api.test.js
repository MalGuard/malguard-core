'use strict';
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const http = require('http');
const path = require('path');
const { startServer } = require('../desktop-app/server.js');

function request(port, method, urlPath, body) {
  return new Promise((resolve, reject) => {
    const raw = body == null ? null : Buffer.from(JSON.stringify(body));
    const req = http.request({
      host: '127.0.0.1', port, method, path: urlPath,
      headers: raw ? {'content-type':'application/json','content-length':String(raw.length)} : {},
    }, res => {
      const chunks=[];
      res.on('data', c=>chunks.push(c));
      res.on('end', ()=>{
        try { resolve({status:res.statusCode, body:JSON.parse(Buffer.concat(chunks).toString('utf8'))}); }
        catch(e){ reject(e); }
      });
    });
    req.on('error',reject);
    if(raw) req.write(raw);
    req.end();
  });
}

async function waitSession(port,id){
  for(let i=0;i<200;i++){
    const r=await request(port,'GET','/api/model-scan/status?id='+encodeURIComponent(id));
    assert.equal(r.status,200);
    const session=r.body.session;
    if(session.state==='completed'||session.state==='failed') return session;
    await new Promise(r=>setTimeout(r,20));
  }
  throw new Error('session polling timeout');
}

(async()=>{
  const server = await startServer(0);
  const tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(),'malguard-model-api-'));
  try {
    const port = server.address().port;

    // Standard is a normal local scan.
    const safeFile = path.join(__dirname,'corpus','benign-config-read.lua');
    let started = await request(port,'POST','/api/model-scan/start',{path:safeFile,model:'standard'});
    assert.equal(started.status,202);
    let session=await waitSession(port,started.body.session.id);
    assert.equal(session.model,'standard');
    assert.equal(session.finalResult.sandboxRequested,false);

    // Plus is the former Pro deep scan and routes suspicious input to Sandbox.
    const suspiciousFile = path.join(__dirname,'corpus','suspicious-cs-powershell.cs');
    started = await request(port,'POST','/api/model-scan/start',{path:suspiciousFile,model:'plus'});
    assert.equal(started.status,202);
    session=await waitSession(port,started.body.session.id);
    assert.equal(session.model,'plus');
    assert.equal(session.finalResult.sandboxRequested,true);
    assert.notEqual(session.finalResult.verdict,'safe');
    assert(session.events.some(e=>e.phase==='sandbox_decision'));

    // Pro goes directly to Sandbox after identity preflight; no static_scan event exists.
    const jsFile=path.join(tempDir,'sample.js');
    await fs.promises.writeFile(jsFile,'console.log("sandbox probe fixture");\n');
    started = await request(port,'POST','/api/model-scan/start',{path:jsFile,model:'pro'});
    assert.equal(started.status,202);
    session=await waitSession(port,started.body.session.id);
    assert.equal(session.model,'pro');
    assert.equal(session.finalResult.sandboxRequested,true);
    assert.notEqual(session.finalResult.verdict,'safe');
    assert(session.events.some(e=>e.phase==='preflight'));
    assert(session.events.some(e=>e.phase==='sandbox_analysis'));
    assert(!session.events.some(e=>e.phase==='static_scan'));

    const invalid=await request(port,'POST','/api/model-scan/start',{path:safeFile,model:'ultra'});
    assert.equal(invalid.status,400);
    assert.equal(invalid.body.code,'INVALID_MODEL');

    // Old /api/pro-scan remains compatible but is explicitly mapped to Plus.
    const legacy=await request(port,'POST','/api/pro-scan/start',{path:safeFile});
    assert.equal(legacy.status,202);
    assert.equal(legacy.body.deprecated,true);
    assert.equal(legacy.body.mappedModel,'plus');
  } finally {
    await fs.promises.rm(tempDir,{recursive:true,force:true});
    await new Promise(resolve=>server.close(resolve));
  }
  console.log('✓ Model scan API: Choose Model semantics, Plus routing, direct Pro Sandbox and legacy compatibility passed');
})().catch(e=>{console.error(e.stack||e);process.exit(1)});
