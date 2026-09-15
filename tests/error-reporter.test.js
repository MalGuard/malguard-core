'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { LocalErrorReporter, safeText } = require('../desktop-app/diagnostics/error-reporter.js');

(async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'malguard-errors-'));
  const reporter = new LocalErrorReporter(root);
  const secret = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890';
  const error = Object.assign(new Error(`failed at C:\\Users\\Test\\secret.txt token ${secret}`), { code: 'SYNTHETIC_FAILURE' });
  const report = await reporter.record(error, { area: 'test', method: 'POST', route: '/api/test' });
  assert.equal(report.code, 'SYNTHETIC_FAILURE');
  assert(!report.message.includes('C:\\Users'));
  assert(!report.message.includes(secret));
  assert(report.message.includes('[path]'));
  assert(report.message.includes('[redacted]'));
  assert.equal(report.context.route, '/api/test');
  assert.equal(Object.prototype.hasOwnProperty.call(report, 'stack'), false);
  assert.equal(Object.prototype.hasOwnProperty.call(report, 'environment'), false);
  const reports = await reporter.list();
  assert.equal(reports.length, 1);
  assert.equal(reports[0].id, report.id);
  assert.equal(safeText('/home/test/private/file.txt'), '[path]');
  fs.rmSync(root, { recursive: true, force: true });
  console.log('✓ Error reporter: local-only diagnostics, redaction and bounded metadata PASS');
})().catch(error => { console.error(error.stack || error); process.exit(1); });
