'use strict';

const assert = require('assert');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');

const diagnosticsRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'malguard-runtime-errors-'));
process.env.MALGUARD_DIAGNOSTICS_ROOT = diagnosticsRoot;
const { startServer, installFatalErrorHandlers } = require('../desktop-app/server.js');

function request({ port, method = 'GET', path: requestPath = '/', body = null }) {
  return new Promise((resolve, reject) => {
    const data = body == null ? null : Buffer.from(body);
    const req = http.request({ host: '127.0.0.1', port, method, path: requestPath, headers: data ? { 'content-type': 'application/json', 'content-length': data.length } : {} }, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, text: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

(async () => {
  const secret = 'THIS_SECRET_MUST_NOT_LEAK_123456789';
  const server = await startServer(0);
  try {
    const response = await request({
      port: server.address().port,
      method: 'POST',
      path: '/api/settings',
      body: `{ "watchRoots": ["${secret}"`,
    });
    assert.equal(response.status, 500);
    const parsed = JSON.parse(response.text);
    assert.equal(parsed.ok, false);
    assert.equal(parsed.code, 'INTERNAL_ERROR');
    assert.equal(parsed.message, 'Internal MalGuard error. See local diagnostics.');
    assert(!response.text.includes('Unexpected'));
    assert(!response.text.includes(secret));

    const diagnosticFiles = fs.readdirSync(diagnosticsRoot).filter(name => name.endsWith('.json'));
    assert.equal(diagnosticFiles.length, 1, 'HTTP 500 must create exactly one local diagnostic record');
    const diagnosticText = fs.readFileSync(path.join(diagnosticsRoot, diagnosticFiles[0]), 'utf8');
    const diagnostic = JSON.parse(diagnosticText);
    assert.equal(diagnostic.context.area, 'http');
    assert.equal(diagnostic.context.method, 'POST');
    assert.equal(diagnostic.context.route, '/api/settings');
    assert.equal(Object.prototype.hasOwnProperty.call(diagnostic, 'stack'), false);
    assert.equal(Object.prototype.hasOwnProperty.call(diagnostic, 'environment'), false);
    assert(!diagnosticText.includes(secret), 'request body secrets must never be persisted in diagnostics');
  } finally {
    await new Promise(resolve => server.close(resolve));
  }

  const records = [];
  const exits = [];
  const reporter = {
    async record(error, context) {
      records.push({ error, context });
    },
  };
  const cleanup = installFatalErrorHandlers(reporter, code => exits.push(code));
  try {
    const installed = process.listeners('unhandledRejection');
    assert(installed.length > 0);
    const handler = installed[installed.length - 1];
    await handler(Object.assign(new Error('synthetic fatal fixture'), { code: 'SYNTHETIC_FATAL' }));
    assert.equal(records.length, 1);
    assert.equal(records[0].context.area, 'unhandledRejection');
    assert.equal(records[0].error.code, 'SYNTHETIC_FATAL');
    assert.deepEqual(exits, [1]);
  } finally {
    cleanup();
    delete process.env.MALGUARD_DIAGNOSTICS_ROOT;
    fs.rmSync(diagnosticsRoot, { recursive: true, force: true });
  }

  console.log('✓ Runtime error integration: generic HTTP 500, persisted local diagnostics, and fatal reporting PASS');
})().catch(error => {
  delete process.env.MALGUARD_DIAGNOSTICS_ROOT;
  fs.rmSync(diagnosticsRoot, { recursive: true, force: true });
  console.error(error.stack || error);
  process.exit(1);
});
