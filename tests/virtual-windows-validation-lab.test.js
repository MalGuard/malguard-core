'use strict';

const assert = require('assert');
const {
  VIRTUAL_WINDOWS_LAB_SCHEMA_VERSION,
  REQUIRED_CHECKS,
  VirtualWindowsValidationLab,
} = require('../desktop-app/sandbox/virtual-windows-validation-lab.js');

(async () => {
  const lab = new VirtualWindowsValidationLab({ timeoutMs: 250, outputQuotaBytes: 4096 });
  const report = await lab.run();

  assert.equal(report.schemaVersion, VIRTUAL_WINDOWS_LAB_SCHEMA_VERSION);
  assert.equal(report.kind, 'malguard-virtual-windows-validation-lab');
  assert.equal(report.mode, 'platform-neutral-windows-sandbox-contract-simulation');
  assert.equal(report.safety.syntheticFixturesOnly, true);
  assert.equal(report.safety.untrustedSamplesExecuted, false);
  assert.equal(report.safety.malwareDownloaded, false);
  assert.equal(report.safety.realWindowsSandboxClaimed, false);
  assert.equal(report.ok, true, JSON.stringify(report, null, 2));
  assert.equal(report.coveragePercent, 100, JSON.stringify(report, null, 2));
  assert.equal(report.passed, REQUIRED_CHECKS.length);
  assert.equal(report.total, REQUIRED_CHECKS.length);

  const names = new Set(report.checks.map(item => item.name));
  for (const required of REQUIRED_CHECKS) {
    assert(names.has(required), `missing virtual Windows check: ${required}`);
  }
  assert(report.checks.every(item => item.ok === true), JSON.stringify(report.checks, null, 2));
  assert(report.limitations.some(text => /not WindowsSandbox\.exe runtime execution/i.test(text)));
  assert(report.limitations.some(text => /separate runtime gate/i.test(text)));

  console.log(`✓ Virtual Windows Validation Lab: ${report.passed}/${report.total} contract checks PASS; engineering coverage=${report.coveragePercent}% without claiming WindowsSandbox.exe execution`);
})().catch(error => {
  console.error(error.stack || error);
  process.exit(1);
});
