'use strict';

const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const PORT = 8765;
const DEBUG_PORT = 9222;
const TARGET_PATH = '/tests/iphone-browser-audit.html';
const TIMEOUT_MS = 90000;

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.zip': 'application/zip',
  '.txt': 'text/plain; charset=utf-8',
};

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function serveStatic() {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      try {
        const url = new URL(req.url, `http://127.0.0.1:${PORT}`);
        const decoded = decodeURIComponent(url.pathname);
        const relative = decoded === '/' ? '/index.html' : decoded;
        const filePath = path.resolve(ROOT, '.' + relative);
        if (filePath !== ROOT && !filePath.startsWith(ROOT + path.sep)) {
          res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
          res.end('forbidden');
          return;
        }
        const stat = fs.statSync(filePath);
        if (!stat.isFile()) throw new Error('not a file');
        res.writeHead(200, {
          'Content-Type': MIME[path.extname(filePath).toLowerCase()] || 'application/octet-stream',
          'Cache-Control': 'no-store',
          'Cross-Origin-Opener-Policy': 'same-origin',
        });
        fs.createReadStream(filePath).pipe(res);
      } catch (_) {
        res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('not found');
      }
    });
    server.once('error', reject);
    server.listen(PORT, '127.0.0.1', () => resolve(server));
  });
}

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

async function main() {
  const server = await serveStatic();
  const chrome = findChrome();
  const profileDir = fs.mkdtempSync(path.join(os.tmpdir(), 'malguard-chrome-'));
  const chromeArgs = [
    '--headless=new',
    '--no-sandbox',
    '--disable-gpu',
    '--disable-dev-shm-usage',
    '--no-first-run',
    '--no-default-browser-check',
    `--remote-debugging-port=${DEBUG_PORT}`,
    `--user-data-dir=${profileDir}`,
    'about:blank',
  ];
  const child = spawn(chrome, chromeArgs, { stdio: ['ignore', 'pipe', 'pipe'] });
  let stderr = '';
  child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });

  let cdp;
  try {
    const page = await waitForDebugger();
    cdp = await openCdp(page.webSocketDebuggerUrl);
    await cdp.send('Runtime.enable');
    await cdp.send('Page.enable');
    const targetUrl = `http://127.0.0.1:${PORT}${TARGET_PATH}`;
    await cdp.send('Page.navigate', { url: targetUrl });

    const deadline = Date.now() + TIMEOUT_MS;
    let status = 'RUNNING';
    while (Date.now() < deadline) {
      try {
        status = await evaluate(cdp.send, 'document.body && document.body.dataset ? document.body.dataset.status : null');
      } catch (_) {
        status = 'RUNNING';
      }
      if (status === 'PASS' || status === 'FAIL') break;
      await sleep(250);
    }

    const payloadText = await evaluate(cdp.send, `JSON.stringify({
      status: document.body && document.body.dataset ? document.body.dataset.status : null,
      overall: document.getElementById('overall') ? document.getElementById('overall').textContent : null,
      raw: document.getElementById('raw') ? document.getElementById('raw').textContent : null
    })`);
    const payload = JSON.parse(payloadText || '{}');
    if (!payload.raw) throw new Error('browser audit did not produce a raw report');
    const report = JSON.parse(payload.raw);

    const failedChecks = Array.isArray(report.checks) ? report.checks.filter((item) => item.ok !== true) : [];
    const uncaught = Array.isArray(report.uncaught) ? report.uncaught : [{ detail: 'missing uncaught array' }];
    const expectedOverall = 'PASS — LIVE BROWSER VALIDATION';
    const ok = payload.status === 'PASS' && payload.overall === expectedOverall && failedChecks.length === 0 && uncaught.length === 0;

    console.log(JSON.stringify({
      browser: chrome,
      targetUrl,
      status: payload.status,
      overall: payload.overall,
      checks: Array.isArray(report.checks) ? report.checks.map((item) => ({ name: item.name, ok: item.ok, detail: item.detail })) : [],
      uncaught,
    }, null, 2));

    if (!ok) {
      throw new Error(`real-browser validation failed: status=${payload.status}, failedChecks=${failedChecks.length}, uncaught=${uncaught.length}`);
    }

    console.log('✓ Real Chromium browser Worker/Self-Test validation PASS');
  } finally {
    try { if (cdp && cdp.ws) cdp.ws.close(); } catch (_) {}
    try { child.kill('SIGKILL'); } catch (_) {}
    await new Promise((resolve) => server.close(resolve));
    try { fs.rmSync(profileDir, { recursive: true, force: true }); } catch (_) {}
    if (stderr && process.env.MALGUARD_BROWSER_DEBUG === '1') process.stderr.write(stderr);
  }
}

main().catch((error) => {
  console.error(error && error.stack ? error.stack : String(error));
  process.exit(1);
});
