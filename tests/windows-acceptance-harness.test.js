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
  assert.match(ps1, /cpu_limit_enforcement/);
  assert.match(ps1, /memory_limit_enforcement/);
  assert.match(ps1, /active_process_limit_enforcement/);

  assert.match(runner, /allowExperimentalDetonation:\s*false/);
  assert.match(runner, /untrustedSamplesExecuted:\s*false/);
  assert.doesNotMatch(runner, /analyzeUntrustedSample\s*\(/);
  assert.doesNotMatch(runner, /\.analyze\s*\(/);

  const backendSource = fs.readFileSync(path.join(root, 'desktop-app', 'sandbox', 'windows-sandbox-backend.js'), 'utf8');
  for (const key of [
    'cpuEnforcementTested',
    'cpuEnforcementPassed',
    'memoryEnforcementTested',
    'memoryEnforcementPassed',
    'activeProcessLimitConfigured',
    'activeProcessLimitTested',
    'activeProcessLimitPassed',
  ]) {
    assert.match(backendSource, new RegExp(key));
  }
  assert.match(backendSource, /CONTAINMENT_PROBE_TIMEOUT[^\n]*30000/);

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
  assert.equal(result.localProbeOk, true);
  assert.equal(result.windowsSandboxReady, true);
  assert.equal(result.releaseReady, true);
  assert.equal(result.ok, true);
  assert.deepEqual(result.blockers, []);

  // A successful local process probe is not enough. Top-level `ok` must remain
  // false until native containment, Windows Sandbox isolation and releaseGrade
  // all prove that the real runtime is certified.
  const pendingBackend = {
    async capabilities() { return { backend: 'fake-windows', available: true, releaseGrade: false, blockers: ['pending'] }; },
    async runContainmentSelfTest() { return { ok: true, details: { synthetic: true } }; },
    async runIsolationSelfTest() { return { ok: false, code: 'WINDOWS_SANDBOX_ISOLATION_PENDING' }; },
  };
  const pendingController = new SandboxController({ windowsBackend: pendingBackend, timeoutMs: 2500, memoryMb: 32 });
  const pending = await pendingController.selfTest();
  assert.equal(pending.localProbeOk, true);
  assert.equal(pending.windowsSandboxReady, false);
  assert.equal(pending.releaseReady, false);
  assert.equal(pending.ok, false);
  assert.ok(pending.blockers.includes('WINDOWS_SANDBOX_ISOLATION_PENDING'));
  assert.ok(pending.blockers.includes('sandbox_release_gate_locked'));

  console.log('✓ Windows acceptance harness: synthetic-only safety, native build plan, post-probe release gate and truthful top-level status PASS');
})().catch(error => {
  console.error(error.stack || error);
  process.exit(1);
});
