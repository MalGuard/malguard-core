'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { SandboxController } = require('./sandbox-controller.js');
const { WindowsSandboxBackend } = require('./windows-sandbox-backend.js');
const { TELEMETRY_SCHEMA_VERSION, validateTelemetry, evaluateTelemetry } = require('./telemetry-validator.js');
const { loadMxcAttestation, evaluateIsolationReadiness } = require('./isolation-readiness.js');
const { VirtualWindowsValidationLab } = require('./virtual-windows-validation-lab.js');

const LAB_SCHEMA_VERSION = '1.1.0';

function check(name, ok, details = null) {
  return { name, ok: ok === true, details };
}

class EmbeddedValidationLab {
  constructor({ timeoutMs = 5000, memoryMb = 48, windowsBackend = null, virtualWindowsLab = null } = {}) {
    this.timeoutMs = timeoutMs;
    this.memoryMb = memoryMb;
    this.windowsBackend = windowsBackend || new WindowsSandboxBackend();
    this.virtualWindowsLab = virtualWindowsLab || new VirtualWindowsValidationLab();
  }

  async run() {
    const startedAt = new Date().toISOString();
    const checks = [];
    const tempRoot = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'malguard-embedded-lab-'));
    const samplePath = path.join(tempRoot, 'synthetic.exe');
    let controllerSelfTest = null;
    let virtualWindows = null;

    try {
      await fs.promises.writeFile(samplePath, Buffer.from('MZ MALGUARD SYNTHETIC VALIDATION FIXTURE\n', 'utf8'), { mode: 0o600 });

      const controller = new SandboxController({
        timeoutMs: this.timeoutMs,
        memoryMb: this.memoryMb,
        windowsBackend: this.windowsBackend,
        allowExperimentalDetonation: false,
      });

      const preflight = await controller.preflightSample(samplePath);
      checks.push(check(
        'synthetic_sample_preflight',
        preflight.ok === true && preflight.revalidated === true && /^[a-f0-9]{64}$/.test(preflight.sha256 || ''),
        preflight.ok ? { size: preflight.size, sha256: preflight.sha256 } : { code: preflight.code }
      ));

      const sessionId = crypto.randomUUID();
      const now = Date.now();
      const validTelemetryRaw = {
        schemaVersion: TELEMETRY_SCHEMA_VERSION,
        sessionId,
        startedAt: new Date(now - 25).toISOString(),
        finishedAt: new Date(now).toISOString(),
        networkPolicy: 'disabled-by-wsb',
        execution: {
          attempted: true,
          started: true,
          timedOut: false,
          exitCode: 0,
          error: null,
          cpuBudgetExceeded: false,
          outputQuotaExceeded: false,
        },
        baselineProcesses: [{ Id: 1, ProcessName: 'synthetic-baseline', Path: null }],
        finalProcesses: [{ Id: 1, ProcessName: 'synthetic-baseline', Path: null }],
        recentFiles: [],
      };
      const telemetry = validateTelemetry(validTelemetryRaw, sessionId);
      const evaluation = telemetry.ok ? evaluateTelemetry(telemetry.telemetry) : null;
      checks.push(check(
        'telemetry_accepts_valid_synthetic_contract',
        telemetry.ok === true && evaluation && evaluation.verdict === 'inconclusive' && evaluation.riskScore === 0,
        telemetry.ok ? evaluation : { code: telemetry.code }
      ));

      const wrongSession = validateTelemetry(validTelemetryRaw, crypto.randomUUID());
      checks.push(check(
        'telemetry_rejects_session_confusion',
        wrongSession.ok === false && wrongSession.code === 'SANDBOX_TELEMETRY_SESSION_MISMATCH',
        { code: wrongSession.code }
      ));

      const wrongNetwork = validateTelemetry({ ...validTelemetryRaw, networkPolicy: 'enabled' }, sessionId);
      checks.push(check(
        'telemetry_rejects_invalid_network_policy',
        wrongNetwork.ok === false && wrongNetwork.code === 'SANDBOX_TELEMETRY_NETWORK_POLICY_INVALID',
        { code: wrongNetwork.code }
      ));

      const xml = this.windowsBackend.buildWsbConfig({
        inputHost: { dir: 'C:\\MalGuardSyntheticInput', samplePath: 'C:\\MalGuardSyntheticInput\\sample.exe' },
        outputHost: 'C:\\MalGuardSyntheticOutput',
        sessionId: '00000000-0000-4000-8000-000000000000',
      });
      const policyContract = [
        '<Networking>Disable</Networking>',
        '<ClipboardRedirection>Disable</ClipboardRedirection>',
        '<VGpu>Disable</VGpu>',
        '<ProtectedClient>Enable</ProtectedClient>',
        '<ReadOnly>true</ReadOnly>',
      ].every(token => xml.includes(token)) && !xml.includes('<Networking>Enable</Networking>');
      checks.push(check('windows_sandbox_policy_contract', policyContract));

      const denied = await controller.analyzeUntrustedSample(samplePath);
      checks.push(check(
        'release_path_fails_closed_without_accepted_backend',
        denied && denied.ok === false && denied.verdict === 'inconclusive' &&
          ['WINDOWS_SANDBOX_UNAVAILABLE', 'HARDENED_SANDBOX_ACCEPTANCE_PENDING'].includes(denied.code),
        denied ? { code: denied.code, verdict: denied.verdict } : null
      ));

      controllerSelfTest = await controller.selfTest();
      checks.push(check(
        'local_process_isolation_probe',
        controllerSelfTest && controllerSelfTest.localProbe && controllerSelfTest.localProbe.ok === true,
        controllerSelfTest && controllerSelfTest.localProbe ? controllerSelfTest.localProbe : null
      ));

      virtualWindows = await this.virtualWindowsLab.run();
      checks.push(check(
        'virtual_windows_contract_lab',
        virtualWindows && virtualWindows.ok === true && virtualWindows.coveragePercent === 100,
        virtualWindows ? {
          mode: virtualWindows.mode,
          passed: virtualWindows.passed,
          total: virtualWindows.total,
          coveragePercent: virtualWindows.coveragePercent,
        } : null
      ));

      const embeddedChecksPassed = checks.every(item => item.ok === true);
      const readiness = evaluateIsolationReadiness({
        embeddedChecksPassed,
        controllerSelfTest,
        mxcAttestation: loadMxcAttestation(),
      });
      const engineeringRequirements = [
        ...checks.map(item => item.ok === true),
        readiness.mxcProcessContainer && readiness.mxcProcessContainer.validated === true,
      ];
      const engineeringValidationPercent = Math.round(
        engineeringRequirements.filter(Boolean).length * 100 / engineeringRequirements.length
      );

      return {
        schemaVersion: LAB_SCHEMA_VERSION,
        kind: 'malguard-embedded-validation-lab',
        startedAt,
        completedAt: new Date().toISOString(),
        safety: {
          syntheticFixturesOnly: true,
          untrustedSamplesExecuted: false,
          malwareDownloaded: false,
          releaseGateBypassed: false,
          realWindowsSandboxClaimedByVirtualLab: false,
        },
        checks,
        engineeringValidationPercent,
        engineeringReady: readiness.engineeringReady,
        windowsSandboxCertified: readiness.windowsSandboxCertified,
        proBehavioralSandboxReady: readiness.proBehavioralSandboxReady,
        releaseReady: readiness.releaseReady,
        virtualWindowsLab: virtualWindows,
        mxcProcessContainer: readiness.mxcProcessContainer,
        scopedReadiness: readiness.scopedReadiness,
        readinessBlockers: readiness.blockers,
        windowsSandbox: controllerSelfTest ? {
          available: !!(controllerSelfTest.windowsSandbox && controllerSelfTest.windowsSandbox.available),
          releaseGrade: !!(controllerSelfTest.windowsSandbox && controllerSelfTest.windowsSandbox.releaseGrade),
          blockers: Array.isArray(controllerSelfTest.blockers) ? controllerSelfTest.blockers : [],
        } : null,
        status: readiness.status,
      };
    } finally {
      await fs.promises.rm(tempRoot, { recursive: true, force: true }).catch(() => {});
    }
  }
}

module.exports = { EmbeddedValidationLab, LAB_SCHEMA_VERSION };
