'use strict';
// Real browser acceptance against the real loopback UI, with synthetic telemetry transport.
const fs=require('fs');const os=require('os');const path=require('path');const {spawn}=require('child_process');const assert=require('assert');
const root=fs.mkdtempSync(path.join(os.tmpdir(),'tsh-browser-'));
process.env.MALGUARD_SETTINGS_FILE=path.join(root,'settings.json');
const app=require('../desktop-app/server');
app.telemetry.endpoint='https://example.invalid/api/v1/installations';
app.telemetry.device=async()=>({architecture:process.arch});
let uploads=[];app.telemetry.fetchImpl=async(url,o)=>{uploads.push({url,payload:JSON.parse(o.body)});return {ok:true};};
async function waitFor(fn){const deadline=Date.now()+15000;while(Date.now()<deadline){const value=await fn();if(value)return value;await new Promise(r=>setTimeout(r,50));}throw Error('browser condition timed out');}
(async()=>{
 const chrome=[process.env.CHROME_PATH,'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe','C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe','/usr/bin/google-chrome','/usr/bin/chromium'].find(p=>p&&fs.existsSync(p));
 if(!chrome)throw Error('real browser unavailable');
 const server=await app.startServer(0);const base=`http://127.0.0.1:${server.address().port}`;const profile=path.join(root,'browser');
 const child=spawn(chrome,['--headless=new','--disable-background-networking','--no-first-run','--remote-debugging-port=0',`--user-data-dir=${profile}`,'about:blank'],{stdio:'ignore'});let ws;
 try{
  const port=await waitFor(()=>{try{return fs.readFileSync(path.join(profile,'DevToolsActivePort'),'utf8').split('\n')[0];}catch(_){return null;}});
  const pages=await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();ws=new WebSocket(pages.find(x=>x.type==='page').webSocketDebuggerUrl);
  await new Promise((resolve,reject)=>{ws.addEventListener('open',resolve,{once:true});ws.addEventListener('error',reject,{once:true});});
  let sequence=0;const pending=new Map();ws.addEventListener('message',e=>{const m=JSON.parse(String(e.data));const p=pending.get(m.id);if(p){pending.delete(m.id);clearTimeout(p.timer);m.error?p.reject(Error(m.error.message)):p.resolve(m.result);}});
  const send=(method,params={})=>new Promise((resolve,reject)=>{const id=++sequence;const timer=setTimeout(()=>{pending.delete(id);reject(Error('CDP timeout'));},10000);pending.set(id,{resolve,reject,timer});ws.send(JSON.stringify({id,method,params}));});
  const evaluate=async expression=>{const r=await send('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});if(r.exceptionDetails)throw Error('browser script failed');return r.result?.value;};
  await send('Page.navigate',{url:base});await waitFor(()=>evaluate("!!document.getElementById('privacyState') && document.getElementById('privacyState').textContent.includes('Anonymous installation ID')"));
  assert.equal(await evaluate("document.getElementById('privacyFirstLaunch').hidden"),false);assert.equal(uploads.length,0);
  assert.equal(await evaluate("document.getElementById('diagnosticsEnabled').checked"),false);
  for(const [width,height] of [[360,800],[390,844],[768,1024],[1440,900]]){
   await send('Emulation.setDeviceMetricsOverride',{width,height,deviceScaleFactor:1,mobile:width<600});
   const fits=await evaluate("document.documentElement.scrollWidth<=innerWidth+1");assert(fits,`privacy first launch overflows ${width}px`);
  }
  await evaluate("document.getElementById('privacyReject').click()");await waitFor(()=>evaluate("document.getElementById('privacyFirstLaunch').hidden"));assert.equal(uploads.length,0);
  await send('Page.reload');await waitFor(()=>evaluate("!!document.getElementById('privacyState') && document.getElementById('privacyState').textContent.includes('Anonymous installation ID')"));assert.equal(await evaluate("document.getElementById('privacyFirstLaunch').hidden"),true);
  await evaluate("document.querySelector('[data-tab=privacy]').click();document.getElementById('diagnosticsEnabled').checked=true;document.getElementById('privacySave').click()");await waitFor(()=>uploads.length===1);
  await evaluate("document.getElementById('privacyPreview').click()");await waitFor(()=>evaluate("document.getElementById('privacyPayload').textContent.startsWith('{')"));
  assert.deepStrictEqual(JSON.parse(await evaluate("document.getElementById('privacyPayload').textContent")),uploads[0].payload);
  for(const [width,height] of [[360,800],[390,844],[768,1024],[1440,900]]){
   await send('Emulation.setDeviceMetricsOverride',{width,height,deviceScaleFactor:1,mobile:width<600});
   assert(await evaluate("document.documentElement.scrollWidth<=innerWidth+1"),`privacy settings overflow ${width}px`);
  }
  await evaluate("document.getElementById('privacyDelete').click()");await waitFor(()=>app.getConfig().diagnostics.enabled===false);assert.equal(uploads.length,2);assert(uploads[1].url.endsWith('/unregister'));
  console.log('TSH Telemetry real browser: first choice, reject, reload persistence, enable, preview equality, delete, 4 viewports PASS');
 }finally{app.telemetry.stop();ws?.close();child.kill();await new Promise(r=>server.close(r));try{fs.rmSync(root,{recursive:true,force:true});}catch(_){/* browser may hold temporary profile locks until exit */}}
})().catch(error=>{console.error('TSH Telemetry real browser acceptance failed:',error.message);process.exitCode=1;});
