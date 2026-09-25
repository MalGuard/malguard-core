'use strict';

const assert = require('assert');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const { Readable } = require('stream');
const { stageScanUpload, validFileName } = require('../desktop-app/local-scan-upload.js');
const { startServer } = require('../desktop-app/server.js');

function request(port, endpoint, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path: endpoint, method: 'POST', headers }, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString()) }));
    });
    req.on('error', reject);
    req.end(body);
  });
}

(async () => {
  const root = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'malguard-upload-test-'));
  const previous = process.env.LOCALAPPDATA;
  process.env.LOCALAPPDATA = root;
  const server = await startServer(0);
  try {
    assert(validFileName('my file.lua'));
    for (const name of ['../secrets', 'CON.txt', 'test.', 'a\\b']) assert(!validFileName(name));
    const port = server.address().port;
    const endpoint = '/api/model-scan/upload?model=standard&name=benign.lua';
    const fixture = Buffer.from('-- harmless local upload fixture\nlocal n = 1\n');
    const headers = { 'x-malguard-local-upload': '1', origin: 'http://127.0.0.1:18777' };
    const denied = await request(port, endpoint, fixture);
    assert.equal(denied.status, 403);
    const wrongOrigin = await request(port, endpoint, fixture, { ...headers, origin: 'https://example.org' });
    assert.equal(wrongOrigin.status, 403);
    const invalid = await request(port, '/api/model-scan/upload?model=standard&name=..%2Fbad', fixture, headers);
    assert.equal(invalid.status, 400);
    const uploaded = await request(port, endpoint, fixture, headers);
    assert.equal(uploaded.status, 202, JSON.stringify(uploaded.body));
    const id = uploaded.body.session.id;
    let session;
    for (let attempt = 0; attempt < 600; attempt++) {
      const response = await fetch(`http://127.0.0.1:${port}/api/model-scan/status?id=${encodeURIComponent(id)}`);
      session = (await response.json()).session;
      if (['completed', 'failed'].includes(session.state) && session.cleanupPending !== true) break; // terminal states are exposed only after upload cleanup
      await new Promise(resolve => setTimeout(resolve, 20));
    }
    assert.equal(session.state, 'completed');
    assert.notEqual(session.cleanupPending, true, 'upload cleanup must finish before the test accepts completion');
    assert.equal(session.model, 'standard');
    for (let attempt = 0; attempt < 100; attempt++) {
      if (!fs.existsSync(session.filePath)) break;
      await new Promise(resolve => setTimeout(resolve, 20));
    }
    assert(!fs.existsSync(session.filePath), 'temporary file should be deleted when scanning finishes');
    const tooLarge = Readable.from([Buffer.alloc(5)]);
    tooLarge.headers = {};
    await assert.rejects(stageScanUpload(tooLarge, 'safe.lua', { maxBytes: 4, root }), /UPLOAD_TOO_LARGE/);
    assert.equal((await fs.promises.readdir(root)).filter(item => item.startsWith('scan-')).length, 0);
  } finally {
    await new Promise(resolve => server.close(resolve));
    if (previous === undefined) delete process.env.LOCALAPPDATA;
    else process.env.LOCALAPPDATA = previous;
    await fs.promises.rm(root, { recursive: true, force: true });
  }
  console.log('✓ Local picker upload: authorized benign scan, cleanup, size limit and origin/name rejection PASS');
})().catch(error => { console.error(error); process.exitCode = 1; });
