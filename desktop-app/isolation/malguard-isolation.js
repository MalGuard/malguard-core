'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { createGameEnvironment } = require('./game-environment.js');

const ISOLATION_VERSION = '0.1.0';
const EXECUTABLE_EXTENSIONS = new Set(['.exe', '.com', '.scr']);

function hashFile(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function quote(value) {
  return `"${String(value).replaceAll('"', '\\"')}"`;
}

function waitForChild(child, timeoutMs) {
  return new Promise((resolve) => {
    let settled = false;
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      try { child.kill(); } catch (_) {}
      resolve({ timedOut: true, code: null, signal: 'TIMEOUT', stdout, stderr });
    }, timeoutMs);
    child.stdout?.on('data', chunk => { stdout += chunk.toString('utf8'); });
    child.stderr?.on('data', chunk => { stderr += chunk.toString('utf8'); });
    child.once('error', error => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ timedOut: false, code: null, signal: 'ERROR', stdout, stderr: `${stderr}${error.message}` });
    });
    child.once('close', (code, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ timedOut: false, code, signal, stdout, stderr });
    });
  });
}

class MalGuardIsolation {
  constructor({ timeoutMs = 20_000, sdkLoader = null } = {}) {
    this.timeoutMs = Math.max(1_000, Number(timeoutMs) || 20_000);
    this.sdkLoader = sdkLoader || (() => import('@microsoft/mxc-sdk'));
  }

  async preflightSample(samplePath) {
    try {
      const resolved = path.resolve(samplePath || '');
      const stat = fs.lstatSync(resolved);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.size <= 0) return { ok: false, code: 'ISOLATION_SAMPLE_INVALID' };
      return { ok: true, path: resolved, size: stat.size, extension: path.extname(resolved).toLowerCase(), sha256: hashFile(resolved) };
    } catch (_) {
      return { ok: false, code: 'ISOLATION_SAMPLE_UNAVAILABLE' };
    }
  }

  async capabilities() {
    if (process.platform !== 'win32') return { ok: false, backend: 'malguard-isolation', releaseGrade: false, code: 'MALGUARD_ISOLATION_WINDOWS_REQUIRED' };
    try {
      const sdk = await this.sdkLoader();
      const support = sdk.getPlatformSupport();
      const processContainer = !!(support && support.isSupported === true && Array.isArray(support.availableMethods) && support.availableMethods.includes('processcontainer'));
      return {
        ok: processContainer,
        backend: 'malguard-isolation',
        isolationPrimitive: 'mxc-processcontainer',
        releaseGrade: processContainer,
        processContainer,
        isolationTier: support && support.isolationTier ? support.isolationTier : null,
        warnings: support && Array.isArray(support.isolationWarnings) ? support.isolationWarnings : [],
        code: processContainer ? null : 'MALGUARD_PROCESSCONTAINER_UNAVAILABLE',
      };
    } catch (error) {
      return { ok: false, backend: 'malguard-isolation', releaseGrade: false, code: 'MALGUARD_ISOLATION_BACKEND_UNAVAILABLE', detail: error.message };
    }
  }

  async selfTest() {
    const capabilities = await this.capabilities();
    return {
      ok: capabilities.releaseGrade === true,
      releaseReady: capabilities.releaseGrade === true,
      isolationVersion: ISOLATION_VERSION,
      productName: 'MalGuard Isolation',
      capabilities,
      blocker: capabilities.releaseGrade === true ? null : capabilities.code,
    };
  }

  async analyzeUntrustedSample(samplePath) {
    const preflight = await this.preflightSample(samplePath);
    if (!preflight.ok) return { ok: false, verdict: 'inconclusive', code: preflight.code, sandboxLaunched: false, sampleExecutionStarted: false, backend: { backend: 'malguard-isolation' } };

    const capabilities = await this.capabilities();
    if (!capabilities.releaseGrade) return { ok: false, verdict: 'inconclusive', code: capabilities.code, sandboxLaunched: false, sampleExecutionStarted: false, backend: capabilities };

    if (!EXECUTABLE_EXTENSIONS.has(preflight.extension)) {
      return {
        ok: false,
        verdict: 'inconclusive',
        code: 'GAME_SIM_LOADER_REQUIRED_FOR_MODULE_TYPE',
        sandboxLaunched: false,
        sampleExecutionStarted: false,
        backend: capabilities,
        preflight,
      };
    }

    const environment = createGameEnvironment(preflight.path);
    try {
      const sdk = await this.sdkLoader();
      const config = sdk.createConfigFromPolicy({
        version: '0.8.0-alpha',
        filesystem: {
          readonlyPaths: [],
          readwritePaths: [environment.root],
        },
        network: { allowOutbound: false, allowLocalNetwork: false },
        timeoutMs: this.timeoutMs,
      }, 'process');
      config.process.commandLine = quote(environment.isolatedSamplePath);
      config.process.cwd = environment.gameRoot;
      const child = sdk.spawnSandboxFromConfig(config, { usePty: false });
      const result = await waitForChild(child, this.timeoutMs);
      const sampleExecutionStarted = result.signal !== 'ERROR';
      return {
        ok: sampleExecutionStarted,
        verdict: 'inconclusive',
        code: sampleExecutionStarted ? 'MALGUARD_ISOLATION_EXECUTION_OBSERVED' : 'MALGUARD_ISOLATION_EXECUTION_FAILED',
        sandboxLaunched: true,
        sampleExecutionStarted,
        isolationLaunched: true,
        gameSimulation: environment.profile,
        execution: { exitCode: result.code, signal: result.signal, timedOut: result.timedOut, stdoutBytes: Buffer.byteLength(result.stdout), stderrBytes: Buffer.byteLength(result.stderr) },
        backend: capabilities,
        releaseGrade: capabilities.releaseGrade === true,
        preflight,
      };
    } finally {
      environment.cleanup();
    }
  }
}

module.exports = { ISOLATION_VERSION, MalGuardIsolation };
