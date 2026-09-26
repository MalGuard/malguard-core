'use strict';
// Runs the real local service and scanner in this OS, without a live telemetry backend.
const {test,after}=require('node:test');
const assert=require('node:assert/strict');const fs=require('fs');const os=require('os');const path=require('path');
const root=fs.mkdtempSync(path.join(os.tmpdir(),'tsh-privacy-runtime-'));
process.env.MALGUARD_SETTINGS_FILE=path.join(root,'settings.json');
process.env.MALGUARD_DIAGNOSTICS_ENDPOINT='https://example.invalid/api/v1/installations';
const app=require('../desktop-app/server');let server;let base;let sent=[];
app.telemetry.fetchImpl=async(url,options)=>{sent.push({url,body:JSON.parse(options.body)});return {ok:true};};
app.telemetry.device=async()=>({architecture:process.arch});
after(async()=>{app.telemetry.stop();if(server)await new Promise(r=>server.close(r));fs.rmSync(root,{recursive:true,force:true});});
async function request(route,body,headers={}) {const r=await fetch(base+route,{method:body?'POST':'GET',headers:{'x-malguard-privacy':'1',...(body?{'content-type':'application/json'}:{}),...headers},body:body?JSON.stringify(body):undefined});return {status:r.status,body:await r.json()};}
test('real app: first launch, rejection, scan, persistence, opt-in, preview, disable',async()=>{
 server=await app.startServer(0);base=`http://127.0.0.1:${server.address().port}`;
 const initial=await request('/api/diagnostics/status');assert.equal(initial.body.diagnostics.enabled,false);assert.equal(initial.body.diagnostics.consentUpdatedAt,null);assert.equal(sent.length,0);
 const html=await (await fetch(base)).text();assert(html.includes('Continue without sharing'));assert(html.includes('Allow diagnostics'));
 assert.equal((await request('/api/diagnostics/consent',{enabled:true,shareRegion:false},{origin:'https://attacker.invalid'})).status,403);
 assert.equal((await request('/api/diagnostics/consent',{enabled:false,shareRegion:false})).status,200);
 assert.equal(sent.length,0);
 const persisted=JSON.parse(fs.readFileSync(process.env.MALGUARD_SETTINGS_FILE,'utf8'));assert.equal(persisted.diagnostics.enabled,false);assert.equal(persisted.diagnostics.installationId,initial.body.diagnostics.installationId);
 // Fixture is a repository-owned Lua config reader; ScannerBridge statically analyzes it.
 const result=await app.scanner.scanPath(path.join(__dirname,'corpus/benign-config-read.lua'),'pro');assert.equal(result.finalVerdict,'safe');assert.equal(sent.length,0);
 assert.equal((await request('/api/status')).status,200);
 await request('/api/diagnostics/consent',{enabled:true,shareRegion:false});
 for(let i=0;i<50&&!sent.length;i++)await new Promise(r=>setTimeout(r,10));
 assert.equal(sent.length,1);const preview=await request('/api/diagnostics/preview');assert.deepEqual(sent[0].body,preview.body.payload);
 const id=app.getConfig().diagnostics.installationId;
 assert.equal(app.settingsStore.loadSync().diagnostics.installationId,id);
 await request('/api/settings',{watchRoots:[],quarantineRoot:path.join(root,'q'),stagingRoot:path.join(root,'s'),diagnostics:{enabled:false}});
 assert.equal(app.getConfig().diagnostics.enabled,true,'generic settings cannot rewrite privacy consent');
 await request('/api/diagnostics/consent',{enabled:false,shareRegion:false});
 assert.equal(sent.length,2);assert(sent[1].url.endsWith('/unregister'));
 await app.telemetry.send('heartbeat');await app.telemetry.send('engine-status');assert.equal(sent.length,2);
 assert.equal((await app.scanner.scanPath(path.join(__dirname,'corpus/benign-config-read.lua'),'pro')).finalVerdict,'safe');
});
