'use strict';

const assert = require('assert');
const http = require('http');
const { startServer, installFatalErrorHandlers } = require('../desktop-app/server.js');

function request({ port, method = 'GET', path = '/', body = null }) {
  return new Promise((resolve, reject) => {
    const data = body == null ? null : Buffer.from(body);
    const req = http.request({ host: '127.0.0.1', port, method, path, headers: data ? { 'content-type': 'application/json', 'content-length': data.length } : {} }, res => {
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
  const server = await startServer(0);
  try {
    const secret = 'THIS_SECRET_MUST_NOT_LEAK_123456789';
    const response = await request({
      port: server.address().port,
      method: 'POST',
      path: '/api/settings',
      body: `{ "watchRoots": [`,
    });
    assert.equal(response.status, 500);
    const parsed = JSON.parse(response.text);
    assert.equal(parsed.ok, false);
    assert.equal(parsed.code, 'INTERNAL_ERROR');
    assert.equal(parsed.message, 'Internal MalGuard error. See local diagnostics.');
    assert(!response.text.includes('Unexpected'));
    assert(!response.text.includes(secret));
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
    const listener = process.listeners('unhandledRejection').find(fn => fn.name === '' || typeof fn === 'function');
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
  }

  console.log('✓ Runtime error integration: generic HTTP 500 and injected fatal reporting PASS');
})().catch(error => { console.error(error.stack || error); process.exit(1); });
