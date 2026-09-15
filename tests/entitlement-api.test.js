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
    assert.equal(status.body.entitlement.plan, 'standard');
    assert.equal(status.body.entitlement.source, 'default-standard');

    const standard = await request(port, 'POST', '/api/model-scan/start', { path: safeFile, model: 'standard' });
    assert.equal(standard.status, 202);
    assert.equal(standard.body.entitlement.plan, 'standard');

    const plus = await request(port, 'POST', '/api/model-scan/start', { path: safeFile, model: 'plus' });
    assert.equal(plus.status, 403); assert.equal(plus.body.code, 'ENTITLEMENT_REQUIRED'); assert.equal(plus.body.requiredPlan, 'plus');

    const pro = await request(port, 'POST', '/api/model-scan/start', { path: safeFile, model: 'pro' });
    assert.equal(pro.status, 403); assert.equal(pro.body.code, 'ENTITLEMENT_REQUIRED'); assert.equal(pro.body.requiredPlan, 'pro');

    const legacy = await request(port, 'POST', '/api/pro-scan/start', { path: safeFile });
    assert.equal(legacy.status, 403); assert.equal(legacy.body.code, 'ENTITLEMENT_REQUIRED'); assert.equal(legacy.body.requiredPlan, 'plus');

    const freeBridge = await request(port, 'POST', '/api/scan-path', { path: safeFile, mode: 'free' });
    assert.equal(freeBridge.status, 200);
    assert.equal(freeBridge.body.ok, true);

    const paidBridge = await request(port, 'POST', '/api/scan-path', { path: safeFile, mode: 'pro' });
    assert.equal(paidBridge.status, 403);
    assert.equal(paidBridge.body.code, 'ENTITLEMENT_REQUIRED');
    assert.equal(paidBridge.body.requiredPlan, 'plus');

    const implicitPaidBridge = await request(port, 'POST', '/api/scan-path', { path: safeFile });
    assert.equal(implicitPaidBridge.status, 403);
    assert.equal(implicitPaidBridge.body.requiredPlan, 'plus');

    const sandboxAnalyze = await request(port, 'POST', '/api/sandbox/analyze', { path: safeFile });
    assert.equal(sandboxAnalyze.status, 403);
    assert.equal(sandboxAnalyze.body.code, 'ENTITLEMENT_REQUIRED');
    assert.equal(sandboxAnalyze.body.requiredPlan, 'pro');

    const sandboxSelfTest = await request(port, 'POST', '/api/sandbox/self-test', {});
    assert.equal(sandboxSelfTest.status, 200);
  } finally { await new Promise(resolve => server.close(resolve)); }

  console.log('✓ Entitlement API: Standard allowed; model, legacy bridge and direct Sandbox paid paths fail closed PASS');
})().catch(error => { console.error(error.stack || error); process.exit(1); });
