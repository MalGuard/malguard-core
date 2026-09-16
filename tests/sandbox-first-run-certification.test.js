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

function fakeGameRunner(backend) {
  return {
    configurationStatus: async () => ({
      ok: true,
      code: 'GTA_CONTEXT_CONFIGURED',
      realGame: true,
      proven: true,
    }),
    analyze: async (samplePath, expectedIdentity) => {
      const result = await backend.analyze(samplePath, expectedIdentity);
      if (result && typeof result === 'object') {
        result.gameContext = { realGame: true, proven: true };
      }
      return result;
    },
  };
}

const unavailableProcessContainer = {
  supportStatus: async () => ({ ok: false, code: 'GTA_PROCESSCONTAINER_UNAVAILABLE', requiresNestedVirtualization: false }),
  configurationStatus: async () => ({ ok: false, code: 'GTA_CONTEXT_NOT_CONFIGURED' }),
};

(async () => {
  const goodBackend = new FakeReleaseGradeBackend();
  const controller = new SandboxController({
    windowsBackend: goodBackend,
    gtaContextRunner: fakeGameRunner(goodBackend),
    processContainerRunner: unavailableProcessContainer,
  });
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
  } finally {
    await fs.promises.rm(dir, { recursive: true, force: true });
  }

  const blockedBackend = new FakeReleaseGradeBackend({ startExecution: false });
  const blockedController = new SandboxController({
    windowsBackend: blockedBackend,
    gtaContextRunner: fakeGameRunner(blockedBackend),
    processContainerRunner: unavailableProcessContainer,
  });
  const blocked = await blockedController.ensureRuntimeCertified();
  assert.equal(blocked.ok, false, 'certification must fail when the harmless sample never starts');
  assert.equal(blocked.executionCertified, false);
  assert(blocked.blockers.some(value => /EXECUTION/i.test(value)), JSON.stringify(blocked.blockers));

  console.log('✓ Sandbox first-run certification: harmless sample execution is mandatory before customer detonation can run');
})().catch(error => {
  console.error(error.stack || error);
  process.exit(1);
});
