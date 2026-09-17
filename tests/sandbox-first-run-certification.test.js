'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { SandboxController } = require('../desktop-app/sandbox/sandbox-controller.js');

class FakeReleaseGradeBackend {
  constructor({ startExecution = true } = {}) {
    this.containment = false;
    this.isolation = false;
    this.startExecution = startExecution;
    this.analyzeCalls = [];
  }

  async capabilities() {
    const releaseGrade = this.containment === true && this.isolation === true;
    return {
      backend: 'windows-sandbox',
      available: true,
      releaseGrade,
      blockers: releaseGrade ? [] : ['acceptance_pending'],
    };
  }

  async runContainmentSelfTest() {
    this.containment = true;
    return { ok: true, details: { synthetic: true } };
  }

  async runIsolationSelfTest() {
    this.isolation = true;
    return { ok: true, details: { sandboxReached: true } };
  }

  async analyze(samplePath, expectedIdentity) {
    this.analyzeCalls.push({ samplePath, expectedIdentity });
    const started = this.startExecution === true;
    return {
      ok: started,
      verdict: 'inconclusive',
      releaseGrade: true,
      sampleSha256: expectedIdentity && expectedIdentity.sha256,
      telemetry: started ? {
        schemaVersion: '1.1.0',
        execution: {
          attempted: true,
          started: true,
          exitCode: 0,
          timedOut: false,
          cpuBudgetExceeded: false,
          outputQuotaExceeded: false,
          error: null,
        },
        baselineProcesses: [],
        finalProcesses: [],
        recentFiles: [],
      } : null,
      code: started ? undefined : 'SYNTHETIC_EXECUTION_NOT_STARTED',
    };
  }
}

(async () => {
  const goodBackend = new FakeReleaseGradeBackend();
  const controller = new SandboxController({ windowsBackend: goodBackend });
  const certification = await controller.ensureRuntimeCertified();
  assert.equal(certification.ok, true, JSON.stringify(certification));
  assert.equal(certification.releaseReady, true);
  assert.equal(certification.coreReady, true);
  assert.equal(certification.executionCertified, true);
  assert.equal(certification.behavioralExecutionReady, true);
  assert.equal(certification.executionProbe.attempted, true);
  assert.equal(certification.executionProbe.started, true);
  assert.equal(certification.executionProbe.exitCode, 0);
  assert.equal(goodBackend.analyzeCalls.length, 1, 'certification must perform one harmless real-execution probe');
  assert.match(path.basename(goodBackend.analyzeCalls[0].samplePath), /malguard-execution-probe\.cmd$/);

  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'malguard-first-real-scan-'));
  try {
    const sample = path.join(dir, 'customer-sample.cmd');
    await fs.promises.writeFile(sample, '@echo off\r\nexit /b 0\r\n');
    const result = await controller.analyzeUntrustedSample(sample);
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.equal(result.sandboxLaunched, true);
    assert.equal(result.sampleExecutionStarted, true);
    assert.equal(result.isolationProvider, 'windows-sandbox');
    assert.equal(goodBackend.analyzeCalls.length, 2, 'customer scan must execute only after execution provider certification');
    assert.equal(path.resolve(goodBackend.analyzeCalls[1].samplePath), path.resolve(sample));
  } finally {
    await fs.promises.rm(dir, { recursive: true, force: true });
  }

  const blockedBackend = new FakeReleaseGradeBackend({ startExecution: false });
  const blockedController = new SandboxController({ windowsBackend: blockedBackend });
  const blocked = await blockedController.ensureRuntimeCertified();
  assert.equal(blocked.ok, true, 'portable isolation core must remain certifiable without Windows execution readiness');
  assert.equal(blocked.coreReady, true);
  assert.equal(blocked.releaseReady, true);
  assert.equal(blocked.executionCertified, false);
  assert.equal(blocked.behavioralExecutionReady, false);
  assert(blocked.runtimeBlockers.some(value => /EXECUTION/i.test(value)), JSON.stringify(blocked.runtimeBlockers));

  const blockedDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'malguard-provider-blocked-'));
  try {
    const sample = path.join(blockedDir, 'customer-sample.cmd');
    await fs.promises.writeFile(sample, '@echo off\r\nexit /b 0\r\n');
    const denied = await blockedController.analyzeUntrustedSample(sample);
    assert.equal(denied.ok, false);
    assert.equal(denied.verdict, 'inconclusive');
    assert.equal(denied.code, 'WINDOWS_GUEST_EXECUTION_PROVIDER_UNAVAILABLE');
    assert.equal(denied.sandboxLaunched, false);
    assert.equal(denied.sampleExecutionStarted, false);
  } finally {
    await fs.promises.rm(blockedDir, { recursive: true, force: true });
  }

  console.log('✓ Sandbox certification: portable isolation core is independent while Windows detonation stays separately fail-closed');
})().catch(error => {
  console.error(error.stack || error);
  process.exit(1);
});
