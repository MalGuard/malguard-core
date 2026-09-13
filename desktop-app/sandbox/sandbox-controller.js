'use strict';

const fs = require('fs');
const path = require('path');
const { createHash } = require('crypto');
const { fork } = require('child_process');
const { WindowsSandboxBackend } = require('./windows-sandbox-backend.js');

const SANDBOX_VERSION = '0.5.0';
const MAX_SAMPLE_BYTES = 64 * 1024 * 1024;
const SUPPORTED_EXTENSIONS = new Set(['.exe', '.com', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js']);

class SandboxController {
  constructor({ timeoutMs = 2500, memoryMb = 48, windowsBackend = null, allowExperimentalDetonation = false } = {}) {
    this.timeoutMs = timeoutMs;
    this.memoryMb = memoryMb;
    this.windowsBackend = windowsBackend || new WindowsSandboxBackend();
    this.allowExperimentalDetonation = allowExperimentalDetonation === true;
  }

  /**
   * A narrow preflight used by the Pro model before direct Sandbox handoff.
   * This is identity/integrity validation, not a normal malware scan.
   */
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

  /**
   * Local synthetic process-isolation probe. This verifies the controller's
   * timeout/memory/process plumbing without executing an untrusted sample.
   */
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
    // Re-read capabilities after the native probes. The backend acceptance gate is
    // intentionally unlocked only by successful probes in this process.
    const windowsSandbox = await this.windowsBackend.capabilities();
    const releaseReady = localProbe.ok && nativeContainment.ok === true && isolationSelfTest.ok === true && windowsSandbox.releaseGrade === true;
    const blockers = [];
    if (!localProbe.ok) blockers.push('local_process_probe_failed');
    if (!nativeContainment.ok) blockers.push(nativeContainment.code || 'native_containment_validation_pending');
    if (!isolationSelfTest.ok) blockers.push(isolationSelfTest.code || 'windows_sandbox_isolation_validation_pending');
    if (windowsSandbox.releaseGrade !== true) blockers.push('sandbox_release_gate_locked');
    return {
      ok: localProbe.ok,
      sandboxVersion: SANDBOX_VERSION,
      localProbe,
      windowsSandbox,
      initialWindowsSandbox,
      nativeContainment,
      isolationSelfTest,
      releaseReady,
      blockers: [...new Set(blockers)],
    };
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
      };
    }
    const capabilities = await this.windowsBackend.capabilities();
    if (!this.allowExperimentalDetonation || capabilities.releaseGrade !== true) {
      return {
        ok: false,
        sandboxVersion: SANDBOX_VERSION,
        verdict: 'inconclusive',
        code: capabilities.available ? 'HARDENED_SANDBOX_ACCEPTANCE_PENDING' : 'WINDOWS_SANDBOX_UNAVAILABLE',
        preflight,
        backend: capabilities,
        note: 'Behavioral execution remains fail-closed until native CPU containment and Windows validation pass.',
      };
    }
    // Experimental mode is intentionally not enabled in the release path. It is
    // useful for Windows engineering validation of the isolated backend only.
    const result = await this.windowsBackend.analyze(preflight.path, preflight);
    if (result && typeof result === 'object') result.preflight = preflight;
    return result;
  }
}

module.exports = { SandboxController, SANDBOX_VERSION, MAX_SAMPLE_BYTES, SUPPORTED_EXTENSIONS };
