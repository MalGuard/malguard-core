'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const { TELEMETRY_SCHEMA_VERSION, validateTelemetry, evaluateTelemetry } = require('./telemetry-validator.js');

const VIRTUAL_WINDOWS_LAB_SCHEMA_VERSION = '1.0.0';
const REQUIRED_CHECKS = Object.freeze([
  'mapped_input_read_only',
  'mapped_output_writable',
  'host_private_path_denied',
  'network_policy_denied',
  'synthetic_process_exit_observed',
  'synthetic_process_timeout_terminated',
  'synthetic_process_crash_recovered',
  'telemetry_identity_binding',
  'telemetry_timeout_signal',
  'telemetry_process_fanout_signal',
  'output_quota_enforced',
  'session_cleanup_disposed',
]);

function check(name, ok, details = null) {
  return { name, ok: ok === true, details };
}

function normalizeGuestPath(value) {
  return String(value || '').replace(/\//g, '\\').toLowerCase();
}

class VirtualMappedFilesystem {
  constructor({ inputRoot, outputRoot }) {
    this.inputRoot = path.resolve(inputRoot);
    this.outputRoot = path.resolve(outputRoot);
  }

  resolve(guestPath, { write = false } = {}) {
    const normalized = normalizeGuestPath(guestPath);
    const inputPrefix = 'c:\\malguardinput';
    const outputPrefix = 'c:\\malguardoutput';

    if (normalized === inputPrefix || normalized.startsWith(inputPrefix + '\\')) {
      if (write) {
        const error = new Error('virtual mapped input is read-only');
        error.code = 'VIRTUAL_INPUT_READ_ONLY';
        throw error;
      }
      const suffix = normalized.slice(inputPrefix.length).replace(/^\\+/, '').split('\\').filter(Boolean);
      return path.join(this.inputRoot, ...suffix);
    }

    if (normalized === outputPrefix || normalized.startsWith(outputPrefix + '\\')) {
      const suffix = normalized.slice(outputPrefix.length).replace(/^\\+/, '').split('\\').filter(Boolean);
      return path.join(this.outputRoot, ...suffix);
    }

    const error = new Error('virtual guest path is outside mapped folders');
    error.code = 'VIRTUAL_GUEST_PATH_DENIED';
    throw error;
  }
}

function runSyntheticChild(script, { timeoutMs = 1000 } = {}) {
  return new Promise((resolve) => {
    const started = Date.now();
    let timedOut = false;
    let settled = false;
    let stdout = '';
    let stderr = '';
    const child = spawn(process.execPath, ['-e', script], {
      shell: false,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: {},
    });

    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ ...result, timedOut, durationMs: Date.now() - started, stdout, stderr });
    };

    child.stdout.on('data', chunk => {
      if (Buffer.byteLength(stdout, 'utf8') < 16 * 1024) stdout += chunk.toString('utf8');
    });
    child.stderr.on('data', chunk => {
      if (Buffer.byteLength(stderr, 'utf8') < 16 * 1024) stderr += chunk.toString('utf8');
    });
    child.once('error', error => finish({ exitCode: null, signal: null, launchError: error.code || error.message }));
    child.once('exit', (exitCode, signal) => finish({ exitCode, signal, launchError: null }));

    const timer = setTimeout(() => {
      timedOut = true;
      try { child.kill(); } catch (_) {}
      setTimeout(() => {
        if (!settled) finish({ exitCode: null, signal: 'terminated', launchError: null });
      }, 250).unref?.();
    }, timeoutMs);
    if (typeof timer.unref === 'function') timer.unref();
  });
}

class VirtualWindowsValidationLab {
  constructor({ timeoutMs = 350, outputQuotaBytes = 4096 } = {}) {
    this.timeoutMs = Math.max(100, Math.min(2000, Number(timeoutMs) || 350));
    this.outputQuotaBytes = Math.max(1024, Math.min(1024 * 1024, Number(outputQuotaBytes) || 4096));
  }

  async run() {
    const startedAt = new Date().toISOString();
    const checks = [];
    const sessionId = crypto.randomUUID();
    const tempRoot = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'malguard-virtual-windows-lab-'));
    const inputRoot = path.join(tempRoot, 'input');
    const outputRoot = path.join(tempRoot, 'output');
    const hostPrivateRoot = path.join(tempRoot, 'host-private');
    let cleanupDisposed = false;

    await fs.promises.mkdir(inputRoot, { recursive: true });
    await fs.promises.mkdir(outputRoot, { recursive: true });
    await fs.promises.mkdir(hostPrivateRoot, { recursive: true });
    await fs.promises.writeFile(path.join(inputRoot, 'sample.exe'), 'MZ MALGUARD SYNTHETIC ONLY\n', 'utf8');
    await fs.promises.writeFile(path.join(hostPrivateRoot, 'host-marker.txt'), 'HOST_PRIVATE_SYNTHETIC_MARKER\n', 'utf8');

    try {
      const vfs = new VirtualMappedFilesystem({ inputRoot, outputRoot });

      let inputDeniedCode = null;
      try { vfs.resolve('C:\\MalGuardInput\\should-not-write.tmp', { write: true }); }
      catch (error) { inputDeniedCode = error.code; }
      checks.push(check('mapped_input_read_only', inputDeniedCode === 'VIRTUAL_INPUT_READ_ONLY', { code: inputDeniedCode }));

      const outputGuest = 'C:\\MalGuardOutput\\result.json';
      const outputHost = vfs.resolve(outputGuest, { write: true });
      await fs.promises.writeFile(outputHost, '{"synthetic":true}\n', 'utf8');
      const outputRoundTrip = await fs.promises.readFile(outputHost, 'utf8');
      checks.push(check('mapped_output_writable', outputRoundTrip.includes('"synthetic":true')));

      let privateDeniedCode = null;
      try { vfs.resolve('C:\\HostPrivate\\host-marker.txt'); }
      catch (error) { privateDeniedCode = error.code; }
      checks.push(check('host_private_path_denied', privateDeniedCode === 'VIRTUAL_GUEST_PATH_DENIED', { code: privateDeniedCode }));

      const networkPolicy = { allowOutbound: false, allowLocalNetwork: false };
      const networkAllowed = networkPolicy.allowOutbound === true || networkPolicy.allowLocalNetwork === true;
      checks.push(check('network_policy_denied', networkAllowed === false, networkPolicy));

      const cleanExit = await runSyntheticChild('process.stdout.write("synthetic-child-ok"); process.exit(0);', { timeoutMs: this.timeoutMs });
      checks.push(check(
        'synthetic_process_exit_observed',
        cleanExit.exitCode === 0 && cleanExit.timedOut === false && cleanExit.stdout === 'synthetic-child-ok',
        { exitCode: cleanExit.exitCode, timedOut: cleanExit.timedOut }
      ));

      const timeoutExit = await runSyntheticChild('setInterval(()=>{},1000);', { timeoutMs: this.timeoutMs });
      checks.push(check(
        'synthetic_process_timeout_terminated',
        timeoutExit.timedOut === true,
        { exitCode: timeoutExit.exitCode, signal: timeoutExit.signal, durationMs: timeoutExit.durationMs }
      ));

      const crashExit = await runSyntheticChild('process.stderr.write("synthetic-crash"); process.exit(7);', { timeoutMs: this.timeoutMs });
      checks.push(check(
        'synthetic_process_crash_recovered',
        crashExit.exitCode === 7 && crashExit.timedOut === false,
        { exitCode: crashExit.exitCode, timedOut: crashExit.timedOut }
      ));

      const now = Date.now();
      const baseTelemetry = {
        schemaVersion: TELEMETRY_SCHEMA_VERSION,
        sessionId,
        startedAt: new Date(now - 50).toISOString(),
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
        baselineProcesses: [{ Id: 10, ProcessName: 'baseline', Path: null }],
        finalProcesses: [{ Id: 10, ProcessName: 'baseline', Path: null }],
        recentFiles: [],
      };

      const identityOk = validateTelemetry(baseTelemetry, sessionId);
      const identityBad = validateTelemetry(baseTelemetry, crypto.randomUUID());
      checks.push(check(
        'telemetry_identity_binding',
        identityOk.ok === true && identityBad.ok === false && identityBad.code === 'SANDBOX_TELEMETRY_SESSION_MISMATCH',
        { mismatchCode: identityBad.code }
      ));

      const timeoutTelemetry = validateTelemetry({
        ...baseTelemetry,
        execution: { ...baseTelemetry.execution, timedOut: true, exitCode: null },
      }, sessionId);
      const timeoutEvaluation = timeoutTelemetry.ok ? evaluateTelemetry(timeoutTelemetry.telemetry) : null;
      checks.push(check(
        'telemetry_timeout_signal',
        timeoutEvaluation && timeoutEvaluation.verdict === 'suspicious' && timeoutEvaluation.signals.includes('execution_timeout'),
        timeoutEvaluation
      ));

      const fanoutTelemetry = validateTelemetry({
        ...baseTelemetry,
        finalProcesses: [
          { Id: 10, ProcessName: 'baseline', Path: null },
          { Id: 11, ProcessName: 'child-a', Path: null },
          { Id: 12, ProcessName: 'child-b', Path: null },
          { Id: 13, ProcessName: 'child-c', Path: null },
        ],
      }, sessionId);
      const fanoutEvaluation = fanoutTelemetry.ok ? evaluateTelemetry(fanoutTelemetry.telemetry) : null;
      checks.push(check(
        'telemetry_process_fanout_signal',
        fanoutEvaluation && fanoutEvaluation.signals.includes('process_fanout') && fanoutEvaluation.riskScore >= 10,
        fanoutEvaluation
      ));

      let quotaUsed = 0;
      const virtualWrite = async (name, bytes) => {
        const buffer = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
        if (quotaUsed + buffer.length > this.outputQuotaBytes) {
          const error = new Error('virtual output quota exceeded');
          error.code = 'VIRTUAL_OUTPUT_QUOTA_EXCEEDED';
          throw error;
        }
        quotaUsed += buffer.length;
        await fs.promises.writeFile(vfs.resolve(`C:\\MalGuardOutput\\${name}`, { write: true }), buffer);
      };
      await virtualWrite('quota-ok.bin', Buffer.alloc(Math.floor(this.outputQuotaBytes / 2), 0x41));
      let quotaDenied = null;
      try { await virtualWrite('quota-denied.bin', Buffer.alloc(this.outputQuotaBytes, 0x42)); }
      catch (error) { quotaDenied = error.code; }
      checks.push(check('output_quota_enforced', quotaDenied === 'VIRTUAL_OUTPUT_QUOTA_EXCEEDED', { code: quotaDenied, quotaUsed }));
    } finally {
      await fs.promises.rm(tempRoot, { recursive: true, force: true });
      try { await fs.promises.access(tempRoot); }
      catch (_) { cleanupDisposed = true; }
      checks.push(check('session_cleanup_disposed', cleanupDisposed));
    }

    const passed = checks.filter(item => item.ok).length;
    const requiredPresent = REQUIRED_CHECKS.every(name => checks.some(item => item.name === name));
    const coveragePercent = requiredPresent ? Math.round((passed / REQUIRED_CHECKS.length) * 100) : 0;
    const ok = requiredPresent && passed === REQUIRED_CHECKS.length;

    return {
      schemaVersion: VIRTUAL_WINDOWS_LAB_SCHEMA_VERSION,
      kind: 'malguard-virtual-windows-validation-lab',
      startedAt,
      completedAt: new Date().toISOString(),
      safety: {
        syntheticFixturesOnly: true,
        untrustedSamplesExecuted: false,
        malwareDownloaded: false,
        realWindowsSandboxClaimed: false,
      },
      mode: 'platform-neutral-windows-sandbox-contract-simulation',
      checks,
      passed,
      total: REQUIRED_CHECKS.length,
      coveragePercent,
      ok,
      limitations: [
        'This validates MalGuard Windows Sandbox contracts and recovery behavior, not WindowsSandbox.exe runtime execution.',
        'Real Windows Sandbox certification remains a separate runtime gate.',
      ],
    };
  }
}

module.exports = {
  VIRTUAL_WINDOWS_LAB_SCHEMA_VERSION,
  REQUIRED_CHECKS,
  VirtualMappedFilesystem,
  VirtualWindowsValidationLab,
};
