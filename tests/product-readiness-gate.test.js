'use strict';

const assert = require('assert');
const path = require('path');
const { spawnSync } = require('child_process');

const tool = path.join(__dirname, '..', 'tools', 'verify-product-readiness.js');
const result = spawnSync(process.execPath, [tool], {
  encoding: 'utf8',
  timeout: 30_000,
  windowsHide: true,
});

if (result.error) throw result.error;
assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
assert.match(result.stdout, /"productReadinessPercent": 100/);
assert.match(result.stdout, /"engineeringValidationPercent": 100/);
assert.match(result.stdout, /"productReleaseReady": true/);
assert.match(result.stdout, /"deployableReleaseProfile": "standard-plus-pro-runtime-gated"/);
assert.match(result.stdout, /"virtualWindowsCoveragePercent": 100/);
assert.match(result.stdout, /"mxcValidated": true/);
assert.match(result.stdout, /host-specific Windows Sandbox runtime remains independently self-certified and fail-closed/);

console.log('✓ Product readiness gate: end-to-end CLI enforcement reports 100% product readiness without bypassing the per-host Sandbox runtime gate');
