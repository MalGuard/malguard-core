'use strict';

const assert = require('assert');
const http = require('http');
const path = require('path');

delete process.env.MALGUARD_ENTITLEMENT_PUBLIC_KEY_PEM;
delete process.env.MALGUARD_ENTITLEMENT_TOKEN;

const { startServer } = require('../desktop-app/server.js');

function request(port, method, urlPath, body) {
  return new Promise((resolve, reject) => {
    const raw = body == null ? null : Buffer.from(JSON.stringify(body));
    const req = http.request({ host: '127.0.0.1', port, method, path: urlPath, headers: raw ? { 'content-type': 'application/json', 'content-length': String(raw.length) } : {} }, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => { try { resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) }); } catch (error) { reject(error); } });
    });
    req.on('error', reject); if (raw) req.write(raw); req.end();
  });
}

(async () => {
  const server = await startServer(0);
  try {
    const port = server.address().port;
    const safeFile = path.join(__dirname, 'corpus', 'benign-config-read.lua');

    const status = await request(port, 'GET', '/api/entitlement/status');
    assert.equal(status.status, 200);
    assert.equal(status.body.entitlement.valid, true);
    assert.equal(status.body.entitlement.plan, 'pro');
    assert.equal(status.body.entitlement.source, 'premium-preview');

    const standard = await request(port, 'POST', '/api/model-scan/start', { path: safeFile, model: 'standard' });
    assert.equal(standard.status, 202);
    assert.equal(standard.body.entitlement.plan, 'pro');

    const plus = await request(port, 'POST', '/api/model-scan/start', { path: safeFile, model: 'plus' });
    assert.equal(plus.status, 202); assert.equal(plus.body.entitlement.plan, 'pro');

    const pro = await request(port, 'POST', '/api/model-scan/start', { path: safeFile, model: 'pro' });
    assert.equal(pro.status, 202); assert.equal(pro.body.entitlement.plan, 'pro');

    const legacy = await request(port, 'POST', '/api/pro-scan/start', { path: safeFile });
    assert.equal(legacy.status, 202); assert.equal(legacy.body.entitlement.plan, 'pro');

    const freeBridge = await request(port, 'POST', '/api/scan-path', { path: safeFile, mode: 'free' });
    assert.equal(freeBridge.status, 200);
    assert.equal(freeBridge.body.ok, true);

    const paidBridge = await request(port, 'POST', '/api/scan-path', { path: safeFile, mode: 'pro' });
    assert.equal(paidBridge.status, 200);
    assert.equal(paidBridge.body.ok, true);

    const implicitPaidBridge = await request(port, 'POST', '/api/scan-path', { path: safeFile });
    assert.equal(implicitPaidBridge.status, 200);
    assert.equal(implicitPaidBridge.body.ok, true);

    const sandboxAnalyze = await request(port, 'POST', '/api/sandbox/analyze', { path: safeFile });
    assert.equal(sandboxAnalyze.status, 200);
    assert.equal(sandboxAnalyze.body.ok, true);

    const sandboxSelfTest = await request(port, 'POST', '/api/sandbox/self-test', {});
    assert.equal(sandboxSelfTest.status, 200);
  } finally { await new Promise(resolve => server.close(resolve)); }

  console.log('✓ Entitlement API: premium preview exposes Standard, Plus, Pro and Sandbox paths PASS');
})().catch(error => { console.error(error.stack || error); process.exit(1); });
