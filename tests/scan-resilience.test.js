'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { ScannerBridge, withTransientIoRetry, ioFailureResult } = require('../desktop-app/scanner-bridge.js');

(async () => {
  const bridge = new ScannerBridge();
  const missing = path.join(os.tmpdir(), `malguard-missing-${Date.now()}.asi`);
  const result = await bridge.scanPath(missing, 'free');
  assert.equal(result.finalVerdict, 'inconclusive');
  assert.equal(result.hardeningError, 'desktop_file_not_found');
  assert.equal(result.io.phase, 'lstat-before-open');

  const denied = ioFailureResult(Object.assign(new Error('denied'), { code: 'EACCES' }), 'pro', 'open');
  assert.equal(denied.finalVerdict, 'inconclusive');
  assert.equal(denied.hardeningError, 'desktop_file_access_denied');

  let attempts = 0;
  const value = await withTransientIoRetry(async () => {
    attempts += 1;
    if (attempts < 3) throw Object.assign(new Error('busy'), { code: 'EBUSY' });
    return 'ok';
  }, 3);
  assert.equal(value, 'ok');
  assert.equal(attempts, 3);

  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'malguard-resilient-scan-'));
  try {
    const target = path.join(temp, 'readable.lua');
    fs.writeFileSync(target, 'local x = 2 + 2\nprint(x)\n');
    const scanned = await bridge.scanPath(target, 'free');
    assert.equal(scanned.resultSchemaVersion, '1.0.0');
    assert.ok(['safe', 'suspicious', 'malicious', 'inconclusive'].includes(scanned.finalVerdict));
    assert.equal(scanned.sourceIdentity.revalidated, true);
    assert.notEqual(scanned.hardeningError, 'desktop_file_io_failed');
    assert.notEqual(scanned.hardeningError, 'desktop_file_access_denied');
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }

  console.log('✓ Scan resilience: missing/access/busy I/O is structured fail-closed, transient busy retries, readable file reaches scanner and is identity-revalidated PASS');
})().catch(error => {
  console.error(error && error.stack ? error.stack : error);
  process.exit(1);
});
