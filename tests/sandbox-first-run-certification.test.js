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
  const automaticBackend = new FakeReleaseGradeBackend();
  const automaticController = new SandboxController({ windowsBackend: automaticBackend, autoCertify: true });
  const automatic = await automaticController.startAutomaticCertification();
  assert.equal(automatic.ok, true, JSON.stringify(automatic));
  assert.equal(automaticController.certificationStatus().automatic.enabled, true);
  assert.equal(automaticController.certificationStatus().state, 'certified');
  assert.equal(automaticBackend.analyzeCalls.length, 1, 'automatic startup certification must execute exactly one harmless fixture');

  const goodBackend = new FakeReleaseGradeBackend();
  const controller = new SandboxController({ windowsBackend: goodBackend });
  const certification = await controller.ensureRuntimeCertified();
  assert.equal(certification.ok, true, JSON.stringify(certification));
  assert.equal(certification.releaseReady, true);
  assert.equal(certification.executionCertified, true);
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
    assert.equal(goodBackend.analyzeCalls.length, 2, 'customer scan must execute only after certification');
    assert.equal(path.resolve(goodBackend.analyzeCalls[1].samplePath), path.resolve(sample));

    const fakeSuccessfulResult = (attempted, started) => ({
      ok: true,
      verdict: 'safe',
      releaseGrade: true,
      sampleSha256: result.preflight.sha256,
      telemetry: {
        schemaVersion: '1.1.0',
        execution: {
          attempted,
          started,
          exitCode: null,
          timedOut: false,
          cpuBudgetExceeded: false,
          outputQuotaExceeded: false,
          error: null,
        },
        baselineProcesses: [],
        finalProcesses: [],
        recentFiles: [],
      },
    });

    goodBackend.analyze = async () => fakeSuccessfulResult(false, false);
    const notAttempted = await controller.analyzeUntrustedSample(sample);
    assert.equal(notAttempted.ok, false);
    assert.equal(notAttempted.verdict, 'inconclusive');
    assert.equal(notAttempted.code, 'SANDBOX_SAMPLE_EXECUTION_NOT_ATTEMPTED');
    assert.equal(notAttempted.sandboxLaunched, false);
    assert.equal(notAttempted.sampleExecutionStarted, false);

    goodBackend.analyze = async () => fakeSuccessfulResult(true, false);
    const notStarted = await controller.analyzeUntrustedSample(sample);
    assert.equal(notStarted.ok, false);
    assert.equal(notStarted.verdict, 'inconclusive');
    assert.equal(notStarted.code, 'SANDBOX_SAMPLE_EXECUTION_NOT_STARTED');
    assert.equal(notStarted.sandboxLaunched, false);
    assert.equal(notStarted.sampleExecutionStarted, false);
  } finally {
    await fs.promises.rm(dir, { recursive: true, force: true });
  }

  const blockedBackend = new FakeReleaseGradeBackend({ startExecution: false });
  const blockedController = new SandboxController({ windowsBackend: blockedBackend, autoCertify: true });
  const blocked = await blockedController.startAutomaticCertification();
  assert.equal(blocked.ok, false, 'automatic certification must fail when the harmless sample never starts');
  assert.equal(blocked.executionCertified, false);
  assert(blocked.blockers.some(value => /EXECUTION/i.test(value)), JSON.stringify(blocked.blockers));

  console.log('✓ Sandbox automatic certification: startup performs harmless real-execution proof before customer detonation can run');
})().catch(error => {
  console.error(error.stack || error);
  process.exit(1);
});
