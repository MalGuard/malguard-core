'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { SandboxController } = require('../desktop-app/sandbox/sandbox-controller.js');

(async () => {
  const root = path.join(__dirname, '..');
  const ps1 = fs.readFileSync(path.join(root, 'tools', 'windows-acceptance.ps1'), 'utf8');
  const runner = fs.readFileSync(path.join(root, 'tools', 'windows-acceptance-runner.js'), 'utf8');

  // The acceptance harness may compile and execute only MalGuard's synthetic
  // probes. It must not install the service or accept a sample/detonation path.
  assert.match(ps1, /untrustedSamplesExecuted\s*=\s*\$false/);
  assert.match(ps1, /serviceInstalled\s*=\s*\$false/);
  assert.match(ps1, /MalGuardSandboxContainmentProbe\.exe/);
  assert.match(ps1, /MalGuardService\.exe/);
  assert.match(ps1, /windows-acceptance-runner\.js/);
  assert.doesNotMatch(ps1, /--install/);
  assert.doesNotMatch(ps1, /Start-Service|New-Service|sc\.exe\s+create/i);

  assert.match(runner, /allowExperimentalDetonation:\s*false/);
  assert.match(runner, /untrustedSamplesExecuted:\s*false/);
  assert.doesNotMatch(runner, /analyzeUntrustedSample\s*\(/);
  assert.doesNotMatch(runner, /\.analyze\s*\(/);

  // Regression for the acceptance-gate bug: capabilities must be read again
  // after native probes complete, otherwise releaseReady can never become true.
  let capabilitiesCalls = 0;
  const fakeBackend = {
    async capabilities() {
      capabilitiesCalls += 1;
      return capabilitiesCalls === 1
        ? { backend: 'fake-windows', releaseGrade: false, blockers: ['pending'] }
        : { backend: 'fake-windows', releaseGrade: true, blockers: [] };
    },
    async runContainmentSelfTest() { return { ok: true, details: { synthetic: true } }; },
    async runIsolationSelfTest() { return { ok: true, details: { synthetic: true } }; },
  };
  const controller = new SandboxController({ windowsBackend: fakeBackend, timeoutMs: 2500, memoryMb: 32 });
  const result = await controller.selfTest();
  assert.equal(capabilitiesCalls, 2);
  assert.equal(result.initialWindowsSandbox.releaseGrade, false);
  assert.equal(result.windowsSandbox.releaseGrade, true);
  assert.equal(result.releaseReady, true);
  assert.deepEqual(result.blockers, []);

  console.log('✓ Windows acceptance harness: synthetic-only safety, native build plan and post-probe release gate PASS');
})().catch(error => {
  console.error(error.stack || error);
  process.exit(1);
});
