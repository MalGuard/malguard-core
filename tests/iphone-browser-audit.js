(function () {
'use strict';

const overallEl = document.getElementById('overall');
const resultsEl = document.getElementById('results');
const rawEl = document.getElementById('raw');
const metaEl = document.getElementById('meta');
const rerunEl = document.getElementById('rerun');
let running = false;

const report = {
  pageVersion: '1.0.0',
  startedAt: null,
  finishedAt: null,
  userAgent: navigator.userAgent,
  origin: location.origin,
  protocol: location.protocol,
  secureContext: window.isSecureContext === true,
  checks: [],
  uncaught: [],
};

function errorText(error) {
  if (!error) return 'unknown error';
  const code = error.code ? String(error.code) + ': ' : '';
  return code + (error.message ? String(error.message) : String(error));
}

function addUncaught(kind, value) {
  report.uncaught.push({ kind, detail: errorText(value), at: new Date().toISOString() });
  renderRaw();
}
window.addEventListener('error', (event) => addUncaught('window-error', event.error || event.message));
window.addEventListener('unhandledrejection', (event) => addUncaught('unhandled-rejection', event.reason));

function renderMeta() {
  metaEl.innerHTML = '';
  const lines = [
    ['Origin', location.origin],
    ['Protocol', location.protocol],
    ['Secure context', String(window.isSecureContext === true)],
    ['Worker API', String(typeof Worker === 'function')],
    ['User agent', navigator.userAgent],
  ];
  for (const [key, value] of lines) {
    const div = document.createElement('div');
    div.className = 'detail';
    div.textContent = key + ': ' + value;
    metaEl.appendChild(div);
  }
}

function renderRaw() {
  rawEl.textContent = JSON.stringify(report, null, 2);
}

function renderCheck(item) {
  const card = document.createElement('div');
  card.className = 'card';
  const row = document.createElement('div');
  row.className = 'row';
  const badge = document.createElement('div');
  badge.className = 'badge ' + (item.ok ? 'pass' : 'fail');
  badge.textContent = item.ok ? 'PASS' : 'FAIL';
  const text = document.createElement('div');
  const title = document.createElement('div');
  title.textContent = item.name;
  title.style.fontWeight = '700';
  const detail = document.createElement('div');
  detail.className = 'detail';
  detail.textContent = item.detail || '';
  text.appendChild(title);
  text.appendChild(detail);
  row.appendChild(badge);
  row.appendChild(text);
  card.appendChild(row);
  resultsEl.appendChild(card);
}

async function check(name, fn) {
  const started = performance.now();
  try {
    const detail = await fn();
    const item = { name, ok: true, detail: String(detail || 'ok'), durationMs: Math.round(performance.now() - started) };
    report.checks.push(item);
    renderCheck(item);
    renderRaw();
    return item;
  } catch (error) {
    const item = { name, ok: false, detail: errorText(error), durationMs: Math.round(performance.now() - started) };
    report.checks.push(item);
    renderCheck(item);
    renderRaw();
    return item;
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message || 'assertion failed');
}

function makeFile(name, text, type) {
  return new File([text], name, { type: type || 'text/plain' });
}

async function fetchFixture() {
  const response = await fetch('fixtures/gtav-benign-scripts.zip', { cache: 'no-store' });
  if (!response.ok) throw new Error('fixture fetch failed: HTTP ' + response.status);
  const bytes = await response.arrayBuffer();
  if (bytes.byteLength < 4) throw new Error('fixture is unexpectedly short');
  const view = new Uint8Array(bytes, 0, 4);
  assert(view[0] === 0x50 && view[1] === 0x4b, 'fixture does not have ZIP magic bytes');
  return new File([bytes], 'gtav-benign-scripts.zip', { type: 'application/zip' });
}

async function testCrashSignaling() {
  await new Promise((resolve, reject) => {
    const worker = new Worker('browser-crash-fixture.js');
    const timer = setTimeout(() => {
      try { worker.terminate(); } catch (_) {}
      reject(new Error('browser did not surface worker crash within 2000ms'));
    }, 2000);
    worker.addEventListener('error', (event) => {
      clearTimeout(timer);
      try { worker.terminate(); } catch (_) {}
      if (!event || typeof event.message !== 'string') {
        reject(new Error('worker error event missing message'));
        return;
      }
      resolve();
    });
  });
  return 'Dedicated Worker crash surfaced through error event';
}

async function testTerminationOfHungWorker() {
  await new Promise((resolve, reject) => {
    const worker = new Worker('browser-hang-fixture.js');
    let ready = false;
    const hard = setTimeout(() => {
      try { worker.terminate(); } catch (_) {}
      reject(new Error('hang fixture failed to initialize'));
    }, 2000);
    worker.addEventListener('message', (event) => {
      if (!event.data || event.data.type !== 'ready' || ready) return;
      ready = true;
      clearTimeout(hard);
      worker.postMessage({ type: 'hang' });
      setTimeout(() => {
        worker.terminate();
        resolve();
      }, 250);
    });
    worker.addEventListener('error', (event) => {
      clearTimeout(hard);
      reject(new Error(event && event.message ? event.message : 'unexpected hang worker error'));
    });
  });
  return 'Hung Dedicated Worker could be hard-terminated by page';
}

async function run() {
  if (running) return;
  running = true;
  rerunEl.disabled = true;
  resultsEl.innerHTML = '';
  report.startedAt = new Date().toISOString();
  report.finishedAt = null;
  report.checks = [];
  report.uncaught = [];
  document.body.dataset.status = 'RUNNING';
  overallEl.className = 'status run';
  overallEl.textContent = 'RUNNING…';
  renderMeta();
  renderRaw();

  try { if (window.MalGuardWorkerScanner) window.MalGuardWorkerScanner.shutdown(); } catch (_) {}

  await check('HTTPS / secure browser context', async () => {
    const local = location.hostname === 'localhost' || location.hostname === '127.0.0.1';
    assert(location.protocol === 'https:' || local, 'open this page from an HTTPS host, not file://');
    assert(window.isSecureContext === true || local, 'browser does not expose a secure context');
    return location.protocol + '//' + location.host;
  });

  await check('Required browser APIs', async () => {
    assert(typeof Worker === 'function', 'Dedicated Worker is unavailable');
    assert(typeof File === 'function', 'File API is unavailable');
    assert(typeof AbortController === 'function', 'AbortController is unavailable');
    assert(typeof fetch === 'function', 'Fetch API is unavailable');
    return 'Worker + File + AbortController + fetch available';
  });

  await check('Runtime contract loaded', async () => {
    const c = window.MalGuardContract;
    assert(c && c.contractVersion, 'MalGuardContract missing');
    assert(c.workerProtocol === 2, 'unexpected worker protocol');
    assert(c.resultSchemaVersion === '1.0.0', 'unexpected result schema');
    return 'contract=' + c.contractVersion + ', schema=' + c.resultSchemaVersion + ', protocol=' + c.workerProtocol;
  });

  await check('Live MalGuard Self-Test', async () => {
    assert(window.MalGuardSelfTest && typeof window.MalGuardSelfTest.run === 'function', 'Self-Test module missing');
    const result = await window.MalGuardSelfTest.run();
    assert(result && result.ok === true && result.passed === true, 'Self-Test failed: ' + JSON.stringify(result && result.checks));
    assert(Array.isArray(result.checks) && result.checks.length >= 8, 'Self-Test returned too few checks');
    return result.checks.map(x => x.id + '=' + (x.ok ? 'PASS' : 'FAIL')).join(', ');
  });

  await check('Worker warmup / isolation contract', async () => {
    const ready = await window.MalGuardWorkerScanner.warmup();
    assert(ready && ready.ready === true, 'worker did not report ready');
    assert(ready.protocol === window.MalGuardContract.workerProtocol, 'worker protocol mismatch');
    assert(ready.resultSchemaVersion === window.MalGuardContract.resultSchemaVersion, 'worker schema mismatch');
    assert(ready.capabilities && ready.capabilities.isolation === 'dedicated_worker', 'worker isolation capability mismatch');
    return 'worker=' + ready.workerVersion + ', isolation=' + ready.capabilities.isolation;
  });

  await check('Benign Lua scan executes inside Web Worker', async () => {
    const file = makeFile('iphone-benign.lua', 'local x=2+2\nprint("GTA V", x)');
    const result = await window.scanFileInWorker(file, 'pro');
    assert(result.finalVerdict === 'safe', 'expected safe, got ' + result.finalVerdict);
    assert(result.execution && result.execution.context === 'web_worker', 'scan did not report web_worker execution');
    return 'verdict=' + result.finalVerdict + ', worker duration=' + result.execution.durationMs + 'ms';
  });

  await check('Suspicious C# does not escape as SAFE', async () => {
    const file = makeFile('iphone-suspicious.cs', 'class T { void Go(){ var p=new System.Diagnostics.ProcessStartInfo(); p.FileName="powershell.exe"; p.Arguments="-EncodedCommand SQBFAFgA"; System.Diagnostics.Process.Start(p); } }');
    const result = await window.scanFileInWorker(file, 'pro');
    assert(result.execution && result.execution.context === 'web_worker', 'scan did not execute in worker');
    assert(result.finalVerdict !== 'safe', 'suspicious sample incorrectly returned SAFE');
    return 'verdict=' + result.finalVerdict;
  });

  await check('Real ZIP fixture fetch + archive analysis in Worker', async () => {
    const zip = await fetchFixture();
    const result = await window.scanFileInWorker(zip, 'pro');
    assert(result.execution && result.execution.context === 'web_worker', 'archive scan did not execute in worker');
    assert(result.finalVerdict === 'safe', 'benign ZIP expected safe, got ' + result.finalVerdict);
    assert(Array.isArray(result.archiveScriptResults) && result.archiveScriptResults.length === 2, 'expected 2 analyzed scripts');
    return 'verdict=safe, archive scripts=' + result.archiveScriptResults.length;
  });

  await check('Worker concurrency gate / race rejection', async () => {
    window.MalGuardWorkerScanner.shutdown();
    const a = makeFile('race-a.lua', 'print("a")');
    const b = makeFile('race-b.lua', 'print("b")');
    const first = window.scanFileInWorker(a, 'pro');
    let busyCode = null;
    try {
      await window.scanFileInWorker(b, 'pro');
    } catch (error) {
      busyCode = error && error.code;
    }
    assert(busyCode === 'WORKER_BUSY', 'second concurrent scan was not rejected with WORKER_BUSY; got ' + busyCode);
    const firstResult = await first;
    assert(firstResult && firstResult.execution && firstResult.execution.context === 'web_worker', 'first race scan failed');
    return 'second scan rejected with WORKER_BUSY';
  });

  await check('Abort terminates scanner and recovers cleanly', async () => {
    await window.MalGuardWorkerScanner.warmup();
    const controller = new AbortController();
    const file = makeFile('abort.lua', 'print("abort test")');
    const pending = window.scanFileInWorker(file, 'pro', { signal: controller.signal });
    queueMicrotask(() => controller.abort());
    let code = null;
    try { await pending; } catch (error) { code = error && error.code; }
    assert(code === 'WORKER_ABORTED', 'expected WORKER_ABORTED, got ' + code);
    assert(window.MalGuardWorkerScanner.hasActiveScan() === false, 'scanner remained active after abort');
    const ready = await window.MalGuardWorkerScanner.warmup();
    assert(ready && ready.ready === true, 'worker did not recover after abort');
    const recovery = await window.scanFileInWorker(makeFile('after-abort.lua', 'print("recovered")'), 'pro');
    assert(recovery.finalVerdict === 'safe', 'post-abort recovery scan failed');
    return 'abort fail-closed + worker restart succeeded';
  });

  await check('Browser surfaces Dedicated Worker crashes', testCrashSignaling);
  await check('Browser can hard-terminate a hung Dedicated Worker', testTerminationOfHungWorker);

  try { if (window.MalGuardWorkerScanner) window.MalGuardWorkerScanner.shutdown(); } catch (_) {}

  report.finishedAt = new Date().toISOString();
  const allPass = report.checks.length > 0 && report.checks.every(x => x.ok) && report.uncaught.length === 0;
  document.body.dataset.status = allPass ? 'PASS' : 'FAIL';
  overallEl.className = 'status ' + (allPass ? 'pass' : 'fail');
  overallEl.textContent = allPass ? 'PASS — LIVE BROWSER VALIDATION' : 'FAIL — SEE CHECKS BELOW';
  renderRaw();
  running = false;
  rerunEl.disabled = false;
}

rerunEl.addEventListener('click', run);
run();
})();
