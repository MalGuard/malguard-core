'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {
  TELEMETRY_SCHEMA_VERSION,
  MAX_RESULT_BYTES,
  validateTelemetry,
  evaluateTelemetry,
} = require('../desktop-app/sandbox/telemetry-validator.js');
const { WindowsSandboxBackend } = require('../desktop-app/sandbox/windows-sandbox-backend.js');
const { SandboxController } = require('../desktop-app/sandbox/sandbox-controller.js');

function baseTelemetry(sessionId) {
  return {
    schemaVersion: TELEMETRY_SCHEMA_VERSION,
    sessionId,
    startedAt: '2026-09-13T10:00:00.000Z',
    finishedAt: '2026-09-13T10:00:05.000Z',
    networkPolicy: 'disabled-by-wsb',
    execution: {
      attempted: true,
      started: true,
      exitCode: 0,
      timedOut: false,
      cpuBudgetExceeded: false,
      outputQuotaExceeded: false,
      error: null,
    },
    baselineProcesses: [{ Id: 1, ProcessName: 'baseline', Path: 'C:\\Windows\\baseline.exe' }],
    finalProcesses: [{ Id: 1, ProcessName: 'baseline', Path: 'C:\\Windows\\baseline.exe' }],
    recentFiles: [],
  };
}

(async () => {
  const sessionId = '00000000-0000-4000-8000-000000000000';
  const valid = validateTelemetry(baseTelemetry(sessionId), sessionId);
  assert.equal(valid.ok, true);
  assert.equal(valid.telemetry.execution.timedOut, false);
  assert.equal(valid.telemetry.execution.attempted, true);
  assert.equal(valid.telemetry.execution.started, true);

  const notAttempted = baseTelemetry(sessionId);
  notAttempted.execution.attempted = false;
  notAttempted.execution.started = false;
  assert.equal(validateTelemetry(notAttempted, sessionId).code, 'SANDBOX_SAMPLE_EXECUTION_NOT_ATTEMPTED');

  const notStarted = baseTelemetry(sessionId);
  notStarted.execution.started = false;
  notStarted.execution.error = 'synthetic launch failure';
  assert.equal(validateTelemetry(notStarted, sessionId).code, 'SANDBOX_SAMPLE_EXECUTION_NOT_STARTED');

  const wrongSchema = baseTelemetry(sessionId);
  wrongSchema.schemaVersion = '0.0.0';
  assert.equal(validateTelemetry(wrongSchema, sessionId).code, 'SANDBOX_TELEMETRY_SCHEMA_MISMATCH');

  const wrongSession = baseTelemetry(sessionId);
  assert.equal(validateTelemetry(wrongSession, '11111111-1111-4111-8111-111111111111').code, 'SANDBOX_TELEMETRY_SESSION_MISMATCH');

  const networkChanged = baseTelemetry(sessionId);
  networkChanged.networkPolicy = 'enabled';
  assert.equal(validateTelemetry(networkChanged, sessionId).code, 'SANDBOX_TELEMETRY_NETWORK_POLICY_INVALID');

  const noisy = JSON.parse(JSON.stringify(valid.telemetry));
  noisy.execution.timedOut = true;
  noisy.finalProcesses = Array.from({ length: 10 }, (_, i) => ({ id: i + 100, processName: `p${i}`, path: null }));
  noisy.recentFiles = Array.from({ length: 30 }, (_, i) => ({ fullName: `C:\\Temp\\f${i}`, length: 1, lastWriteTimeUtc: '2026-09-13T10:00:01.000Z' }));
  const noisyAssessment = evaluateTelemetry(noisy);
  assert.equal(noisyAssessment.verdict, 'suspicious');
  assert(noisyAssessment.riskScore >= 25);

  const quietAssessment = evaluateTelemetry(valid.telemetry);
  assert.equal(quietAssessment.verdict, 'inconclusive', 'quiet telemetry must not prove SAFE');

  const tmp = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'malguard-sandbox-hardening-'));
  try {
    const backend = new WindowsSandboxBackend({ sessionRoot: tmp, maxOutputBytes: MAX_RESULT_BYTES, maxOutputFiles: 2 });
    const caps = await backend.capabilities();
    assert.equal(caps.releaseGrade, false);
    assert.equal(caps.isolation.cpuHardCap, false);
    assert.equal(caps.isolation.outputQuota.enforcement, 'host-watchdog');

    const output = path.join(tmp, 'output');
    await fs.promises.mkdir(output, { recursive: true });
    await fs.promises.writeFile(path.join(output, 'a'), '1');
    await fs.promises.writeFile(path.join(output, 'b'), '2');
    assert.equal((await backend._measureOutput(output)).ok, true);
    await fs.promises.writeFile(path.join(output, 'c'), '3');
    assert.equal((await backend._measureOutput(output)).code, 'SANDBOX_OUTPUT_QUOTA_EXCEEDED');

    const sample = path.join(tmp, 'synthetic.exe');
    await fs.promises.writeFile(sample, Buffer.from('MZ synthetic fixture only'));
    let mismatch = null;
    try {
      await backend._prepareSession(sample, { sha256: '0'.repeat(64) });
    } catch (error) {
      mismatch = error;
    }
    assert(mismatch && mismatch.code === 'SANDBOX_SAMPLE_IDENTITY_MISMATCH');

    const controller = new SandboxController({ windowsBackend: backend, allowExperimentalDetonation: true });
    const denied = await controller.analyzeUntrustedSample(sample);
    assert.equal(denied.ok, false);
    assert.equal(denied.verdict, 'inconclusive');
    assert(['WINDOWS_SANDBOX_UNAVAILABLE', 'HARDENED_SANDBOX_ACCEPTANCE_PENDING'].includes(denied.code));
  } finally {
    await fs.promises.rm(tmp, { recursive: true, force: true });
  }

  console.log('✓ Sandbox telemetry requires real sample start, validates quotas/identity and preserves release safety gate PASS');
})().catch(error => {
  console.error(error.stack || error);
  process.exit(1);
});
