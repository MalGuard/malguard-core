'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const { createHash } = require('crypto');
const {
  TELEMETRY_SCHEMA_VERSION,
  MAX_RESULT_BYTES,
  validateTelemetry,
  evaluateTelemetry,
} = require('./telemetry-validator.js');

const BACKEND_VERSION = '0.3.0';
const RESULT_SCHEMA_VERSION = TELEMETRY_SCHEMA_VERSION;
const DEFAULT_MAX_OUTPUT_BYTES = 2 * 1024 * 1024;
const DEFAULT_MAX_OUTPUT_FILES = 8;

function xmlEscape(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

async function sha256Bytes(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

async function readStableRegularFile(filePath, maxBytes) {
  const before = await fs.promises.lstat(filePath);
  if (!before.isFile() || before.isSymbolicLink()) {
    const error = new Error('sandbox input must be a regular non-symlink file');
    error.code = 'INVALID_SANDBOX_SAMPLE';
    throw error;
  }
  if (before.size <= 0 || before.size > maxBytes) {
    const error = new Error(before.size <= 0 ? 'sandbox sample is empty' : 'sandbox sample exceeds size cap');
    error.code = before.size <= 0 ? 'SANDBOX_SAMPLE_EMPTY' : 'SANDBOX_SAMPLE_TOO_LARGE';
    throw error;
  }

  const flags = fs.constants.O_RDONLY | (Number.isInteger(fs.constants.O_NOFOLLOW) ? fs.constants.O_NOFOLLOW : 0);
  const handle = await fs.promises.open(filePath, flags);
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || opened.size !== before.size || opened.mtimeMs !== before.mtimeMs) {
      const error = new Error('sandbox input changed before staging read');
      error.code = 'SANDBOX_SAMPLE_CHANGED_BEFORE_STAGING';
      throw error;
    }
    const bytes = await handle.readFile();
    const afterHandle = await handle.stat();
    const afterPath = await fs.promises.lstat(filePath);
    if (bytes.length !== opened.size || afterHandle.size !== opened.size || afterHandle.mtimeMs !== opened.mtimeMs ||
        !afterPath.isFile() || afterPath.isSymbolicLink() || afterPath.size !== opened.size || afterPath.mtimeMs !== opened.mtimeMs) {
      const error = new Error('sandbox input changed during staging read');
      error.code = 'SANDBOX_SAMPLE_CHANGED_DURING_STAGING';
      throw error;
    }
    return { bytes, stat: opened, sha256: await sha256Bytes(bytes) };
  } finally {
    await handle.close().catch(() => {});
  }
}

class WindowsSandboxBackend {
  constructor({
    timeoutMs = 30000,
    observeSeconds = 8,
    memoryMb = 2048,
    sessionRoot = null,
    maxOutputBytes = DEFAULT_MAX_OUTPUT_BYTES,
    maxOutputFiles = DEFAULT_MAX_OUTPUT_FILES,
    preserveSessions = false,
    containmentProbePath = null,
  } = {}) {
    this.timeoutMs = Math.max(5000, Number(timeoutMs) || 30000);
    this.observeSeconds = Math.max(1, Math.min(20, Number(observeSeconds) || 8));
    this.memoryMb = Math.max(2048, Number(memoryMb) || 2048);
    this.maxOutputBytes = Math.max(MAX_RESULT_BYTES, Number(maxOutputBytes) || DEFAULT_MAX_OUTPUT_BYTES);
    this.maxOutputFiles = Math.max(1, Math.min(64, Number(maxOutputFiles) || DEFAULT_MAX_OUTPUT_FILES));
    this.preserveSessions = preserveSessions === true;
    this.sessionRoot = path.resolve(sessionRoot || path.join(os.tmpdir(), 'malguard-windows-sandbox'));
    this.harnessSource = path.join(__dirname, 'windows-sandbox', 'guest-harness.ps1');
    this.selfTestHarnessSource = path.join(__dirname, 'windows-sandbox', 'self-test-harness.ps1');
    this.containmentProbePath = path.resolve(containmentProbePath || path.join(__dirname, 'bin', 'MalGuardSandboxContainmentProbe.exe'));
    // Windows-native acceptance is deliberately process-local. A new process must
    // prove containment + Windows Sandbox isolation again before releaseGrade can
    // become true. We never trust a stale on-disk flag.
    this._acceptance = { containment: false, isolation: false };
  }

  executablePath() {
    const systemRoot = process.env.SystemRoot || process.env.WINDIR || 'C:\\Windows';
    return path.join(systemRoot, 'System32', 'WindowsSandbox.exe');
  }

  async capabilities() {
    const platform = process.platform;
    const executable = this.executablePath();
    let executablePresent = false;
    if (platform === 'win32') {
      try { await fs.promises.access(executable, fs.constants.X_OK); executablePresent = true; } catch (_) {}
    }
    const available = platform === 'win32' && executablePresent;
    let containmentProbePresent = false;
    if (platform === 'win32') {
      try { await fs.promises.access(this.containmentProbePath, fs.constants.X_OK); containmentProbePresent = true; } catch (_) {}
    }
    const containmentAccepted = available && containmentProbePresent && this._acceptance.containment === true;
    const isolationAccepted = available && this._acceptance.isolation === true;
    const releaseGrade = containmentAccepted && isolationAccepted;
    const blockers = [];
    if (!available) {
      blockers.push('windows_sandbox_backend_unavailable_on_current_host', 'windows_native_validation_pending');
    } else {
      if (!containmentProbePresent) blockers.push('native_job_object_cpu_cap_pending');
      else if (!containmentAccepted) blockers.push('native_job_object_self_test_pending');
      if (!isolationAccepted) blockers.push('windows_sandbox_isolation_self_test_pending');
    }
    return {
      backend: 'windows-sandbox',
      backendVersion: BACKEND_VERSION,
      platform,
      executablePresent,
      available,
      containmentProbePresent,
      hardened: releaseGrade,
      releaseGrade,
      acceptance: {
        containment: containmentAccepted,
        isolation: isolationAccepted,
        scope: 'current-process',
      },
      isolation: {
        network: 'disabled',
        clipboard: 'disabled',
        mappedInput: 'read-only',
        disposableVm: true,
        memoryMb: this.memoryMb,
        wallClockTimeoutMs: this.timeoutMs,
        cpuHardCap: containmentAccepted,
        outputQuota: {
          enforcement: 'host-watchdog',
          maxBytes: this.maxOutputBytes,
          maxFiles: this.maxOutputFiles,
        },
        telemetryResultMaxBytes: MAX_RESULT_BYTES,
      },
      blockers,
    };
  }


  async runContainmentSelfTest() {
    this._acceptance.containment = false;
    if (process.platform !== 'win32') {
      return { ok: false, code: 'CONTAINMENT_PROBE_UNSUPPORTED_HOST' };
    }
    try { await fs.promises.access(this.containmentProbePath, fs.constants.X_OK); }
    catch (_) { return { ok: false, code: 'CONTAINMENT_PROBE_NOT_INSTALLED' }; }

    return new Promise((resolve) => {
      let stdout = '';
      let stderrBytes = 0;
      let settled = false;
      const child = spawn(this.containmentProbePath, ['--self-test-json'], {
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
        shell: false,
      });
      const finish = (result) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        try { if (!child.killed) child.kill(); } catch (_) {}
        resolve(result);
      };
      child.stdout.on('data', chunk => {
        stdout += chunk.toString('utf8');
        if (Buffer.byteLength(stdout, 'utf8') > 64 * 1024) finish({ ok: false, code: 'CONTAINMENT_PROBE_OUTPUT_TOO_LARGE' });
      });
      child.stderr.on('data', chunk => {
        stderrBytes += chunk.length;
        if (stderrBytes > 64 * 1024) finish({ ok: false, code: 'CONTAINMENT_PROBE_STDERR_TOO_LARGE' });
      });
      const timer = setTimeout(() => finish({ ok: false, code: 'CONTAINMENT_PROBE_TIMEOUT' }), 30000);
      child.once('error', error => finish({ ok: false, code: 'CONTAINMENT_PROBE_LAUNCH_FAILED', detail: error.message }));
      child.once('exit', (code) => {
        if (settled) return;
        let parsed;
        try { parsed = JSON.parse(stdout.trim()); }
        catch (_) { return finish({ ok: false, code: 'CONTAINMENT_PROBE_JSON_INVALID' }); }
        const required = ['jobObjectCreated','cpuHardCapConfigured','cpuEnforcementTested','cpuEnforcementPassed','memoryLimitConfigured','memoryEnforcementTested','memoryEnforcementPassed','activeProcessLimitConfigured','activeProcessLimitTested','activeProcessLimitPassed','killOnCloseConfigured','processCreatedSuspended','assignedBeforeResume','childResumed','childTerminated'];
        const ok = code === 0 && parsed && parsed.schemaVersion === '1.0.0' && parsed.ok === true && required.every(key => parsed[key] === true);
        this._acceptance.containment = ok;
        finish(ok ? { ok: true, details: parsed } : { ok: false, code: 'CONTAINMENT_PROBE_FAILED', details: parsed || null, exitCode: code });
      });
    });
  }

  buildIsolationSelfTestConfig({ inputHost, outputHost, sessionId }) {
    const command = [
      'powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned',
      '-File C:\\MalGuardSelfTest\\self-test-harness.ps1',
      '-InputPath C:\\MalGuardSelfTest',
      '-OutputPath C:\\MalGuardSelfTestOutput\\result.json',
      '-SessionId ' + sessionId,
    ].join(' ');
    return `<?xml version="1.0" encoding="utf-8"?>\n<Configuration>\n  <VGpu>Disable</VGpu>\n  <Networking>Disable</Networking>\n  <AudioInput>Disable</AudioInput>\n  <VideoInput>Disable</VideoInput>\n  <PrinterRedirection>Disable</PrinterRedirection>\n  <ClipboardRedirection>Disable</ClipboardRedirection>\n  <ProtectedClient>Enable</ProtectedClient>\n  <MemoryInMB>${this.memoryMb}</MemoryInMB>\n  <MappedFolders>\n    <MappedFolder><HostFolder>${xmlEscape(inputHost)}</HostFolder><SandboxFolder>C:\\MalGuardSelfTest</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder>\n    <MappedFolder><HostFolder>${xmlEscape(outputHost)}</HostFolder><SandboxFolder>C:\\MalGuardSelfTestOutput</SandboxFolder><ReadOnly>false</ReadOnly></MappedFolder>\n  </MappedFolders>\n  <LogonCommand><Command>${xmlEscape(command)}</Command></LogonCommand>\n</Configuration>\n`;
  }

  async runIsolationSelfTest() {
    this._acceptance.isolation = false;
    const caps = await this.capabilities();
    if (!caps.available) return { ok: false, code: 'WINDOWS_SANDBOX_UNAVAILABLE' };

    const sessionId = crypto.randomUUID();
    const root = path.join(this.sessionRoot, `selftest-${sessionId}`);
    const inputDir = path.join(root, 'input');
    const outputDir = path.join(root, 'output');
    const wsbPath = path.join(root, 'selftest.wsb');
    const resultPath = path.join(outputDir, 'result.json');
    await fs.promises.mkdir(inputDir, { recursive: true, mode: 0o700 });
    await fs.promises.mkdir(outputDir, { recursive: true, mode: 0o700 });
    await fs.promises.copyFile(this.selfTestHarnessSource, path.join(inputDir, 'self-test-harness.ps1'), fs.constants.COPYFILE_EXCL);
    await fs.promises.writeFile(wsbPath, this.buildIsolationSelfTestConfig({ inputHost: inputDir, outputHost: outputDir, sessionId }), { flag: 'wx', mode: 0o600 });

    return new Promise((resolve) => {
      let settled = false;
      let poller = null;
      let timer = null;
      const child = spawn(this.executablePath(), [wsbPath], { stdio: 'ignore', windowsHide: true, shell: false });
      const finish = async (result) => {
        if (settled) return;
        settled = true;
        if (poller) clearInterval(poller);
        if (timer) clearTimeout(timer);
        try { if (!child.killed) child.kill(); } catch (_) {}
        await fs.promises.rm(root, { recursive: true, force: true }).catch(() => {});
        resolve(result);
      };
      poller = setInterval(async () => {
        try {
          const stat = await fs.promises.lstat(resultPath);
          if (!stat.isFile() || stat.isSymbolicLink() || stat.size <= 0 || stat.size > 64 * 1024) {
            return finish({ ok: false, code: 'SANDBOX_SELF_TEST_RESULT_INVALID' });
          }
          const raw = await fs.promises.readFile(resultPath, 'utf8');
          const parsed = JSON.parse(raw.replace(/^\uFEFF/, ''));
          const ok = parsed && parsed.schemaVersion === '1.0.0' && parsed.sessionId === sessionId &&
            parsed.sandboxReached === true && parsed.inputReadOnly === true && parsed.outputWritable === true &&
            parsed.networkDefaultRoutePresent === false && parsed.error == null;
          this._acceptance.isolation = ok;
          return finish(ok ? { ok: true, details: parsed } : { ok: false, code: 'SANDBOX_SELF_TEST_FAILED', details: parsed || null });
        } catch (_) {}
      }, 250);
      if (typeof poller.unref === 'function') poller.unref();
      timer = setTimeout(() => finish({ ok: false, code: 'SANDBOX_SELF_TEST_TIMEOUT' }), 20000);
      child.once('error', error => finish({ ok: false, code: 'SANDBOX_SELF_TEST_LAUNCH_FAILED', detail: error.message }));
    });
  }

  buildWsbConfig({ inputHost, outputHost, sessionId }) {
    const command = [
      'powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned',
      '-File C:\\MalGuardInput\\guest-harness.ps1',
      '-SamplePath C:\\MalGuardInput\\sample' + path.extname(inputHost.samplePath).toLowerCase(),
      '-OutputPath C:\\MalGuardOutput\\result.json',
      '-SessionId ' + sessionId,
      '-ObserveSeconds ' + this.observeSeconds,
    ].join(' ');
    return `<?xml version="1.0" encoding="utf-8"?>\n<Configuration>\n  <VGpu>Disable</VGpu>\n  <Networking>Disable</Networking>\n  <AudioInput>Disable</AudioInput>\n  <VideoInput>Disable</VideoInput>\n  <PrinterRedirection>Disable</PrinterRedirection>\n  <ClipboardRedirection>Disable</ClipboardRedirection>\n  <ProtectedClient>Enable</ProtectedClient>\n  <MemoryInMB>${this.memoryMb}</MemoryInMB>\n  <MappedFolders>\n    <MappedFolder><HostFolder>${xmlEscape(inputHost.dir)}</HostFolder><SandboxFolder>C:\\MalGuardInput</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder>\n    <MappedFolder><HostFolder>${xmlEscape(outputHost)}</HostFolder><SandboxFolder>C:\\MalGuardOutput</SandboxFolder><ReadOnly>false</ReadOnly></MappedFolder>\n  </MappedFolders>\n  <LogonCommand><Command>${xmlEscape(command)}</Command></LogonCommand>\n</Configuration>\n`;
  }

  async _prepareSession(samplePath, expectedIdentity = null) {
    const ext = path.extname(samplePath).toLowerCase();
    const allowed = new Set(['.exe','.com','.scr','.bat','.cmd','.ps1','.vbs','.js']);
    if (!allowed.has(ext)) {
      const error = new Error('sample type is not supported by the behavioral backend');
      error.code = 'SANDBOX_SAMPLE_TYPE_UNSUPPORTED';
      throw error;
    }

    const stable = await readStableRegularFile(samplePath, 64 * 1024 * 1024);
    if (expectedIdentity && expectedIdentity.sha256 && stable.sha256 !== expectedIdentity.sha256) {
      const error = new Error('sample identity changed after sandbox preflight');
      error.code = 'SANDBOX_SAMPLE_IDENTITY_MISMATCH';
      throw error;
    }

    const sessionId = crypto.randomUUID();
    const root = path.join(this.sessionRoot, sessionId);
    const inputDir = path.join(root, 'input');
    const outputDir = path.join(root, 'output');
    await fs.promises.mkdir(inputDir, { recursive: true, mode: 0o700 });
    await fs.promises.mkdir(outputDir, { recursive: true, mode: 0o700 });
    const copiedSample = path.join(inputDir, `sample${ext}`);
    await fs.promises.writeFile(copiedSample, stable.bytes, { flag: 'wx', mode: 0o400 });
    await fs.promises.copyFile(this.harnessSource, path.join(inputDir, 'guest-harness.ps1'), fs.constants.COPYFILE_EXCL);
    const copiedSha256 = await sha256Bytes(await fs.promises.readFile(copiedSample));
    if (stable.sha256 !== copiedSha256) {
      const error = new Error('sandbox staging integrity mismatch');
      error.code = 'SANDBOX_STAGING_INTEGRITY_FAILED';
      throw error;
    }
    const wsbPath = path.join(root, 'session.wsb');
    const wsb = this.buildWsbConfig({ inputHost: { dir: inputDir, samplePath: copiedSample }, outputHost: outputDir, sessionId });
    await fs.promises.writeFile(wsbPath, wsb, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
    return { sessionId, root, inputDir, outputDir, copiedSample, originalSha256: stable.sha256, wsbPath };
  }

  async _measureOutput(outputDir) {
    let count = 0;
    let bytes = 0;
    const entries = await fs.promises.readdir(outputDir, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isFile()) {
        if (!entry.isDirectory()) return { ok: false, code: 'SANDBOX_OUTPUT_NONREGULAR_ENTRY' };
        // Nested output is intentionally forbidden to keep the mapped write surface bounded.
        return { ok: false, code: 'SANDBOX_OUTPUT_NESTED_ENTRY' };
      }
      count += 1;
      const stat = await fs.promises.lstat(path.join(outputDir, entry.name));
      if (!stat.isFile() || stat.isSymbolicLink()) return { ok: false, code: 'SANDBOX_OUTPUT_NONREGULAR_ENTRY' };
      bytes += stat.size;
      if (count > this.maxOutputFiles || bytes > this.maxOutputBytes) {
        return { ok: false, code: 'SANDBOX_OUTPUT_QUOTA_EXCEEDED', count, bytes };
      }
    }
    return { ok: true, count, bytes };
  }

  async _readValidatedResult(resultPath, sessionId) {
    const stat = await fs.promises.lstat(resultPath);
    if (!stat.isFile() || stat.isSymbolicLink()) return { ok: false, code: 'SANDBOX_RESULT_NOT_REGULAR' };
    if (stat.size <= 0 || stat.size > MAX_RESULT_BYTES) return { ok: false, code: 'SANDBOX_RESULT_SIZE_INVALID' };
    const raw = await fs.promises.readFile(resultPath, 'utf8');
    if (Buffer.byteLength(raw, 'utf8') > MAX_RESULT_BYTES) return { ok: false, code: 'SANDBOX_RESULT_SIZE_INVALID' };
    let parsed;
    try { parsed = JSON.parse(raw.replace(/^\uFEFF/, '')); }
    catch (_) { return { ok: false, code: 'SANDBOX_RESULT_JSON_INVALID' }; }
    return validateTelemetry(parsed, sessionId);
  }

  async _cleanupSession(session) {
    if (!session || this.preserveSessions) return;
    await fs.promises.rm(session.root, { recursive: true, force: true }).catch(() => {});
  }

  async analyze(samplePath, expectedIdentity = null) {
    const caps = await this.capabilities();
    // Safety gate: the release backend cannot execute untrusted files until the
    // missing native CPU-control and Windows validation blockers are cleared.
    if (!caps.releaseGrade) {
      return {
        ok: false,
        verdict: 'inconclusive',
        code: caps.available ? 'HARDENED_WINDOWS_SANDBOX_ACCEPTANCE_PENDING' : 'WINDOWS_SANDBOX_UNAVAILABLE',
        backend: caps,
      };
    }

    let session = null;
    try {
      session = await this._prepareSession(path.resolve(samplePath), expectedIdentity);
    } catch (error) {
      return { ok: false, verdict: 'inconclusive', code: error.code || 'SANDBOX_STAGING_FAILED', backend: caps };
    }
    const resultPath = path.join(session.outputDir, 'result.json');

    return new Promise((resolve) => {
      let settled = false;
      let poller = null;
      let timer = null;
      const child = spawn(this.executablePath(), [session.wsbPath], { stdio: 'ignore', windowsHide: true });

      const finish = async (result) => {
        if (settled) return;
        settled = true;
        if (poller) clearInterval(poller);
        if (timer) clearTimeout(timer);
        try { if (!child.killed) child.kill(); } catch (_) {}
        await this._cleanupSession(session);
        resolve(result);
      };

      poller = setInterval(async () => {
        try {
          const quota = await this._measureOutput(session.outputDir);
          if (!quota.ok) {
            await finish({ ok: false, verdict: 'inconclusive', code: quota.code, backend: caps, sampleSha256: session.originalSha256 });
            return;
          }
          try { await fs.promises.access(resultPath, fs.constants.R_OK); } catch (_) { return; }
          const checked = await this._readValidatedResult(resultPath, session.sessionId);
          if (!checked.ok) {
            if (checked.code === 'SANDBOX_RESULT_JSON_INVALID') return; // allow atomic write to finish
            await finish({ ok: false, verdict: 'inconclusive', code: checked.code, backend: caps, sampleSha256: session.originalSha256 });
            return;
          }
          const assessment = evaluateTelemetry(checked.telemetry);
          await finish({
            ok: true,
            verdict: assessment.verdict,
            releaseGrade: caps.releaseGrade === true,
            backend: caps,
            sampleSha256: session.originalSha256,
            telemetry: checked.telemetry,
            behaviorAssessment: assessment,
            note: 'Behavior telemetry can raise suspicion but never proves SAFE on its own.',
          });
        } catch (_) {}
      }, 250);
      if (typeof poller.unref === 'function') poller.unref();

      timer = setTimeout(() => {
        finish({ ok: false, verdict: 'inconclusive', code: 'WINDOWS_SANDBOX_TIMEOUT', backend: caps, sampleSha256: session.originalSha256 });
      }, this.timeoutMs);
      child.once('error', error => finish({ ok: false, verdict: 'inconclusive', code: 'WINDOWS_SANDBOX_LAUNCH_FAILED', detail: error.message, backend: caps }));
    });
  }
}

module.exports = {
  WindowsSandboxBackend,
  BACKEND_VERSION,
  RESULT_SCHEMA_VERSION,
  DEFAULT_MAX_OUTPUT_BYTES,
  DEFAULT_MAX_OUTPUT_FILES,
  xmlEscape,
  readStableRegularFile,
};
