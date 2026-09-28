 'use strict';
const fs=require('fs');
const os=require('os');
const path=require('path');
const assert=require('assert');
const {spawn}=require('child_process');
const {startServer}=require('../desktop-app/server');
const DEBUG_PORT=9333;
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
function findChrome() {
  const candidates = [
    process.env.CHROME_PATH,
    '/usr/bin/google-chrome',
    '/usr/bin/google-chrome-stable',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
  ].filter(Boolean);
  for (const candidate of candidates) {
    try {
      if (fs.existsSync(candidate)) return candidate;
    } catch (_) {}
  }
  throw new Error('Chrome/Chromium executable not found on runner');
}

async function fetchJson(url) {
  const response = await fetch(url, { cache: 'no-store' });
  if (!response.ok) throw new Error(`HTTP ${response.status} from ${url}`);
  return response.json();
}

async function waitForDebugger() {
  const deadline = Date.now() + 20000;
  let lastError = null;
  while (Date.now() < deadline) {
    try {
      const pages = await fetchJson(`http://127.0.0.1:${DEBUG_PORT}/json/list`);
      const page = pages.find((item) => item.type === 'page' && item.webSocketDebuggerUrl);
      if (page) return page;
    } catch (error) {
      lastError = error;
    }
    await sleep(200);
  }
  throw new Error(`Chrome DevTools endpoint unavailable${lastError ? ': ' + lastError.message : ''}`);
}

async function openCdp(url) {
  const ws = new WebSocket(url);
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('CDP WebSocket connect timeout')), 10000);
    ws.addEventListener('open', () => {
      clearTimeout(timer);
      resolve();
    }, { once: true });
    ws.addEventListener('error', () => {
      clearTimeout(timer);
      reject(new Error('CDP WebSocket connection failed'));
    }, { once: true });
  });

  let nextId = 1;
  const pending = new Map();
  ws.addEventListener('message', (event) => {
    let message;
    try { message = JSON.parse(String(event.data)); } catch (_) { return; }
    if (!message.id || !pending.has(message.id)) return;
    const entry = pending.get(message.id);
    pending.delete(message.id);
    if (message.error) entry.reject(new Error(message.error.message || 'CDP error'));
    else entry.resolve(message.result || {});
  });

  function send(method, params = {}) {
    return new Promise((resolve, reject) => {
      const id = nextId++;
      pending.set(id, { resolve, reject });
      ws.send(JSON.stringify({ id, method, params }));
      setTimeout(() => {
        if (!pending.has(id)) return;
        pending.delete(id);
        reject(new Error(`CDP command timeout: ${method}`));
      }, 10000);
    });
  }

  return { ws, send };
}

async function evaluate(send, expression) {
  const result = await send('Runtime.evaluate', {
    expression,
    returnByValue: true,
    awaitPromise: true,
  });
  if (result.exceptionDetails) throw new Error('Runtime.evaluate exception');
  return result.result ? result.result.value : undefined;
}


(async()=>{
 const chrome=findChrome();
 const server=await startServer(0);
 const profile=fs.mkdtempSync(path.join(os.tmpdir(),'mg-unified-browser-'));
 const child=spawn(chrome,['--headless=new','--no-sandbox','--disable-dev-shm-usage','--no-first-run',`--remote-debugging-port=${DEBUG_PORT}`,`--user-data-dir=${profile}`,'about:blank'],{stdio:'ignore'});
 let cdp;
 const errors=[];
 try{
  const page=await waitForDebugger();cdp=await openCdp(page.webSocketDebuggerUrl);
  cdp.ws.addEventListener('message',e=>{const m=JSON.parse(String(e.data));if(m.method==='Runtime.exceptionThrown')errors.push(m.params.exceptionDetails.text);});
  await cdp.send('Runtime.enable');await cdp.send('Page.enable');
  for(const width of [360,390,820,1440]){
   await cdp.send('Emulation.setDeviceMetricsOverride',{width,height:900,deviceScaleFactor:1,mobile:width<500});
   await cdp.send('Page.navigate',{url:`http://127.0.0.1:${server.address().port}`});
   let ready=false;
   for(let n=0;n<100;n++){ready=await evaluate(cdp.send,`!!document.getElementById('status') && !document.getElementById('status').textContent.includes('Loading')`);if(ready)break;await sleep(100);}
   assert(ready,'desktop did not load');
   assert.equal(await evaluate(cdp.send,'document.documentElement.scrollWidth > innerWidth'),false,`overflow at ${width}`);
   assert.equal(await evaluate(cdp.send,"!!document.getElementById('scanModel')"),false);
   await evaluate(cdp.send,String.raw`(async()=>{const dt=new DataTransfer();dt.items.add(new File(['-- harmless UI acceptance fixture\nlocal n=1'],'benign.lua',{type:'text/plain'}));document.getElementById('scanFile').files=dt.files;await document.getElementById('scanBtn').onclick();})()`);
   assert((await evaluate(cdp.send,"document.getElementById('scanOut').textContent")).includes('No safety verdict'));
   assert((await evaluate(cdp.send,"document.getElementById('modelFinal').textContent")).includes('MalwareBazaar:'));
   assert.equal(await evaluate(cdp.send,'document.documentElement.scrollWidth > innerWidth'),false,`result overflow at ${width}`);
   console.log(`PASS ${width}px: rendered scan, visible reputation/limits, no tiers or overflow`);
  }
  assert.deepEqual(errors,[]);
 }finally{
  if(cdp)cdp.ws.close();child.kill();await new Promise(r=>server.close(r));
  fs.rmSync(profile,{recursive:true,force:true});
 }
})().catch(e=>{console.error(e);process.exit(1)});
