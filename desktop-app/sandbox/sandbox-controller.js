'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { createHash } = require('crypto');
const { fork } = require('child_process');
const { WindowsSandboxBackend } = require('./windows-sandbox-backend.js');
const { RealGtaContextRunner } = require('./gta-real-context-runner.js');

const SANDBOX_VERSION = '0.7.0';
const MAX_SAMPLE_BYTES = 64 * 1024 * 1024;
const SUPPORTED_EXTENSIONS = new Set(['.exe', '.com', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js']);

class SandboxController {
  constructor({ timeoutMs = 2500, memoryMb = 48, windowsBackend = null, gtaContextRunner = null } = {}) {
    this.timeoutMs = timeoutMs;
    this.memoryMb = memoryMb;
    this.windowsBackend = windowsBackend || new WindowsSandboxBackend();
    this.gtaContextRunner = gtaContextRunner || new RealGtaContextRunner({ windowsBackend: this.windowsBackend });
    this._certification = {
      state: 'not_run',
      ok: false,
      sandboxVersion: SANDBOX_VERSION,
      certifiedAt: null,
      blockers: ['sandbox_runtime_not_certified'],
    };
    this._certificationPromise = null;
  }

  certificationStatus() {
    const current = this._certification || {};
    return {
      state: current.state || 'not_run',
      ok: current.ok === true,
      sandboxVersion: SANDBOX_VERSION,
      certifiedAt: current.certifiedAt || null,
      windowsSandboxReady: current.windowsSandboxReady === true,
      executionCertified: current.executionCertified === true,
      blockers: Array.isArray(current.blockers) ? [...current.blockers] : [],
      executionProbe: current.executionProbe ? { ...current.executionProbe } : null,
    };
  }

  async preflightSample(samplePath) {
    if (typeof samplePath !== 'string' || !samplePath.trim()) {
      return { ok: false, sandboxVersion: SANDBOX_VERSION, code: 'SANDBOX_SAMPLE_PATH_REQUIRED' };
    }
    const resolved = path.resolve(samplePath);
    let before;
    try {
      before = await fs.promises.lstat(resolved);
    } catch (error) {
      return { ok: false, sandboxVersion: SANDBOX_VERSION, code: 'SANDBOX_SAMPLE_NOT_FOUND' };
    }
    if (before.isSymbolicLink() || !before.isFile()) {
      return { ok: false, sandboxVersion: SANDBOX_VERSION, code: 'INVALID_SANDBOX_SAMPLE' };
    }
    if (before.size <= 0) {
      return { ok: false, sandboxVersion: SANDBOX_VERSION, code: 'SANDBOX_SAMPLE_EMPTY' };
    }
    if (before.size > MAX_SAMPLE_BYTES) {
      return { ok: false, sandboxVersion: SANDBOX_VERSION, code: 'SANDBOX_SAMPLE_TOO_LARGE', size: before.size };
    }
    const extension = path.extname(resolved).toLowerCase();
    if (!SUPPORTED_EXTENSIONS.has(extension)) {
      return { ok: false, sandboxVersion: SANDBOX_VERSION, code: 'SANDBOX_SAMPLE_TYPE_UNSUPPORTED', extension };
    }

    const flags = fs.constants.O_RDONLY | (Number.isInteger(fs.constants.O_NOFOLLOW) ? fs.constants.O_NOFOLLOW : 0);
    let handle;
    try {
      handle = await fs.promises.open(resolved, flags);
      const firstStat = await handle.stat();
      if (!firstStat.isFile() || firstStat.size !== before.size || firstStat.mtimeMs !== before.mtimeMs) {
        return { ok: false, sandboxVersion: SANDBOX_VERSION, code: 'SANDBOX_SAMPLE_CHANGED_BEFORE_READ' };
      }
      const bytes = await handle.readFile();
      const afterStat = await handle.stat();
      if (bytes.length !== firstStat.size || afterStat.size !== firstStat.size || afterStat.mtimeMs !== firstStat.mtimeMs) {
        return { ok: false, sandboxVersion: SANDBOX_VERSION, code: 'SANDBOX_SAMPLE_CHANGED_DURING_READ' };
      }
      const sha256 = createHash('sha256').update(bytes).digest('hex');
      let finalStat;
      try { finalStat = await fs.promises.lstat(resolved); } catch (_) {
        return { ok: false, sandboxVersion: SANDBOX_VERSION, code: 'SANDBOX_SAMPLE_DISAPPEARED_AFTER_READ' };
      }
      if (!finalStat.isFile() || finalStat.isSymbolicLink() || finalStat.size !== before.size || finalStat.mtimeMs !== before.mtimeMs) {
        return { ok: false, sandboxVersion: SANDBOX_VERSION, code: 'SANDBOX_SAMPLE_CHANGED_AFTER_READ' };
      }
      return {
        ok: true,
        sandboxVersion: SANDBOX_VERSION,
        path: resolved,
        name: path.basename(resolved),
        extension,
        size: bytes.length,
        sha256,
        revalidated: true,
      };
    } catch (error) {
      return { ok: false, sandboxVersion: SANDBOX_VERSION, code: error.code || 'SANDBOX_PREFLIGHT_READ_FAILED' };
    } finally {
      if (handle) await handle.close().catch(() => {});
    }
  }

  async _runHarmlessExecutionProbe() {
    const root = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'malguard-sandbox-execution-cert-'));
    const samplePath = path.join(root, 'malguard-execution-probe.cmd');
    try {
      await fs.promises.writeFile(samplePath, '@echo off\r\nexit /b 0\r\n', { flag: 'wx', mode: 0o600 });
      const preflight = await this.preflightSample(samplePath);
      if (!preflight.ok) {
        return { ok: false, code: preflight.code || 'SANDBOX_EXECUTION_PROBE_PREFLIGHT_FAILED' };
      }
      const result = await this.windowsBackend.analyze(preflight.path, preflight);
      const execution = result && result.telemetry && result.telemetry.execution;
      const ok = !!(result && result.ok === true && execution &&
        execution.attempted === true && execution.started === true &&
        execution.timedOut !== true && execution.error == null && execution.exitCode === 0);
      if (!ok) {
        return {
          ok: false,
          code: result && result.code ? result.code : 'SANDBOX_EXECUTION_PROBE_FAILED',
          sandboxLaunched: false,
          attempted: !!(execution && execution.attempted === true),
          started: !!(execution && execution.started === true),
          exitCode: execution ? execution.exitCode : null,
        };
      }
      return {
        ok: true,
        code: 'SANDBOX_EXECUTION_CERTIFIED',
        sandboxLaunched: true,
        attempted: true,
        started: true,
        exitCode: 0,
        sampleSha256: result.sampleSha256 || preflight.sha256,
      };
    } finally {
      await fs.promises.rm(root, { recursive: true, force: true }).catch(() => {});
    }
  }

  async selfTest() {
    const worker = path.join(__dirname, 'synthetic-probe-worker.js');
    const localProbe = await new Promise((resolve) => {
      const child = fork(worker, [], {
        stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
        env: { MALGUARD_SYNTHETIC_PROBE: '1' },
        execArgv: [`--max-old-space-size=${this.memoryMb}`],
      });
      let settled = false;
      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        child.kill('SIGKILL');
        resolve({ ok: false, code: 'SANDBOX_PROBE_TIMEOUT' });
      }, this.timeoutMs);
      child.once('message', (message) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        child.kill();
        const ok = !!(message && message.ok && message.probe === 'malguard-synthetic-isolation');
        resolve({ ok, backend: 'process-isolation-probe', details: message || null });
      });
      child.once('error', (error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve({ ok: false, code: 'SANDBOX_PROBE_ERROR', detail: error.message });
      });
    });

    const initialWindowsSandbox = await this.windowsBackend.capabilities();
    const nativeContainment = typeof this.windowsBackend.runContainmentSelfTest === 'function'
      ? await this.windowsBackend.runContainmentSelfTest()
      : { ok: false, code: 'CONTAINMENT_SELF_TEST_UNAVAILABLE' };
    const isolationSelfTest = typeof this.windowsBackend.runIsolationSelfTest === 'function'
      ? await this.windowsBackend.runIsolationSelfTest()
      : { ok: false, code: 'ISOLATION_SELF_TEST_UNAVAILABLE' };
    const windowsSandbox = await this.windowsBackend.capabilities();
    const localProbeOk = localProbe.ok === true;
    const windowsSandboxReady = nativeContainment.ok === true
      && isolationSelfTest.ok === true
      && windowsSandbox.releaseGrade === true;
    const executionProbe = windowsSandboxReady
      ? await this._runHarmlessExecutionProbe()
      : { ok: false, code: 'SANDBOX_EXECUTION_SELF_TEST_BLOCKED', sandboxLaunched: false, attempted: false, started: false, exitCode: null };
    const executionCertified = executionProbe.ok === true
      && executionProbe.sandboxLaunched === true
      && executionProbe.attempted === true
      && executionProbe.started === true
      && executionProbe.exitCode === 0;
    const releaseReady = localProbeOk && windowsSandboxReady && executionCertified;
    const blockers = [];
    if (!localProbeOk) blockers.push('local_process_probe_failed');
    if (!nativeContainment.ok) blockers.push(nativeContainment.code || 'native_containment_validation_pending');
    if (!isolationSelfTest.ok) blockers.push(isolationSelfTest.code || 'windows_sandbox_isolation_validation_pending');
    if (windowsSandbox.releaseGrade !== true) blockers.push('sandbox_release_gate_locked');
    if (!executionCertified) blockers.push(executionProbe.code || 'windows_sandbox_execution_validation_pending');

    const result = {
      ok: releaseReady,
      state: releaseReady ? 'certified' : 'failed',
      sandboxVersion: SANDBOX_VERSION,
      certifiedAt: releaseReady ? new Date().toISOString() : null,
      localProbeOk,
      windowsSandboxReady,
      executionCertified,
      localProbe,
      windowsSandbox,
      initialWindowsSandbox,
      nativeContainment,
      isolationSelfTest,
      executionProbe,
      releaseReady,
      blockers: [...new Set(blockers)],
    };
    this._certification = result;
    return result;
  }

  async ensureRuntimeCertified({ force = false } = {}) {
    if (!force && this._certification && this._certification.ok === true) return this._certification;
    if (this._certificationPromise) return this._certificationPromise;
    this._certification = {
      state: 'running',
      ok: false,
      sandboxVersion: SANDBOX_VERSION,
      certifiedAt: null,
      blockers: [],
    };
    this._certificationPromise = this.selfTest()
      .finally(() => { this._certificationPromise = null; });
    return this._certificationPromise;
  }

  async analyzeUntrustedSample(samplePath) {
    const preflight = await this.preflightSample(samplePath);
    if (!preflight.ok) {
      return {
        ok: false,
        sandboxVersion: SANDBOX_VERSION,
        verdict: 'inconclusive',
        code: preflight.code,
        preflight,
        sandboxLaunched: false,
        sampleExecutionStarted: false,
      };
    }

    const certification = await this.ensureRuntimeCertified();
    if (!certification || certification.ok !== true) {
      const capabilities = await this.windowsBackend.capabilities();
      return {
        ok: false,
        sandboxVersion: SANDBOX_VERSION,
        verdict: 'inconclusive',
        code: capabilities.available ? 'WINDOWS_SANDBOX_CERTIFICATION_FAILED' : 'WINDOWS_SANDBOX_UNAVAILABLE',
        preflight,
        backend: capabilities,
        certification: this.certificationStatus(),
        sandboxLaunched: false,
        sampleExecutionStarted: false,
        note: 'MalGuard refuses behavioral execution until this process proves native containment, Windows Sandbox isolation and real sample launch with a harmless fixture.',
      };
    }

    const capabilities = await this.windowsBackend.capabilities();
    if (capabilities.releaseGrade !== true) {
      return {
        ok: false,
        sandboxVersion: SANDBOX_VERSION,
        verdict: 'inconclusive',
        code: capabilities.available ? 'HARDENED_SANDBOX_ACCEPTANCE_PENDING' : 'WINDOWS_SANDBOX_UNAVAILABLE',
        preflight,
        backend: capabilities,
        certification: this.certificationStatus(),
        sandboxLaunched: false,
        sampleExecutionStarted: false,
      };
    }

    const gameConfiguration = await this.gtaContextRunner.configurationStatus();
    if (!gameConfiguration.ok) {
      return {
        ok: false,
        sandboxVersion: SANDBOX_VERSION,
        verdict: 'inconclusive',
        code: gameConfiguration.code || 'GTA_CONTEXT_NOT_CONFIGURED',
        preflight,
        backend: capabilities,
        certification: this.certificationStatus(),
        gameContext: gameConfiguration,
        sandboxLaunched: false,
        sampleExecutionStarted: false,
        note: 'Behavioral detonation is fail-closed until a real GTA V installation is explicitly configured. Synthetic game fixtures cannot certify a real game-context verdict.',
      };
    }

    const result = await this.gtaContextRunner.analyze(preflight.path, preflight);
    if (result && typeof result === 'object') {
      result.preflight = preflight;
      result.certification = this.certificationStatus();
      result.gameContext = result.gameContext || gameConfiguration;
      const execution = result.telemetry && result.telemetry.execution;
      result.sampleExecutionStarted = !!(execution && execution.started === true);
      result.sandboxLaunched = result.ok === true && result.sampleExecutionStarted === true &&
        result.gameContext && result.gameContext.realGame === true && result.gameContext.proven === true;
      if (result.ok === true && (!execution || execution.attempted !== true || execution.started !== true || result.sandboxLaunched !== true)) {
        return {
          ok: false,
          sandboxVersion: SANDBOX_VERSION,
          verdict: 'inconclusive',
          code: 'REAL_GTA_CONTEXT_EXECUTION_NOT_PROVEN',
          preflight,
          backend: capabilities,
          certification: this.certificationStatus(),
          gameContext: result.gameContext || gameConfiguration,
          sandboxLaunched: false,
          sampleExecutionStarted: false,
        };
      }
    }
    return result;
  }
}

module.exports = { SandboxController, SANDBOX_VERSION, MAX_SAMPLE_BYTES, SUPPORTED_EXTENSIONS };
