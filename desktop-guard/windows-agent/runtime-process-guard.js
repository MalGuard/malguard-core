'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const { normalizeAbsolute, isWithin } = require('./path-guard.js');

const RUNTIME_CODE_EXTENSIONS = new Set(['.exe', '.dll', '.asi']);

function normalizeVerdict(result) {
  const value = String(result && (result.verdict || result.finalVerdict) || 'INCONCLUSIVE').toUpperCase();
  return ['SAFE', 'SUSPICIOUS', 'MALICIOUS', 'INCONCLUSIVE'].includes(value) ? value : 'INCONCLUSIVE';
}

class RuntimeGameProcessGuard {
  constructor({
    roots,
    scanner,
    trustedPath,
    onIncident = null,
    platform = process.platform,
    serviceMode = false,
    intervalMs = 1000,
    snapshotProvider = null,
    terminateProcess = null,
  } = {}) {
    if (!Array.isArray(roots) || !roots.length) throw new TypeError('roots required');
    if (typeof scanner !== 'function') throw new TypeError('scanner required');
    if (typeof trustedPath !== 'function') throw new TypeError('trustedPath required');
    this.roots = roots.map(normalizeAbsolute);
    this.scanner = scanner;
    this.trustedPath = trustedPath;
    this.onIncident = typeof onIncident === 'function' ? onIncident : null;
    this.platform = platform;
    this.serviceMode = serviceMode === true;
    this.intervalMs = Math.max(500, Number(intervalMs) || 1000);
    this.helper = path.join(__dirname, 'windows-tools', 'runtime-process-helper.ps1');
    this.snapshotProvider = snapshotProvider || (() => this._runHelper('Snapshot'));
    this.terminateProcess = terminateProcess || ((pid, expectedPath) => this._runHelper('Terminate', { pid, expectedPath }));
    this.timer = null;
    this.active = false;
    this.externalCache = new Map();
    this.state = {
      ok: false,
      active: false,
      healthy: false,
      monitoredProcesses: 0,
      lastAction: null,
      lastIncident: null,
      lastError: null,
      moduleLoadProtection: true,
      memoryOnlyInjectionProtection: false,
      state: 'stopped',
      reason: null,
      timestamp: Date.now(),
    };
  }

  capabilities() {
    return {
      platform: this.platform,
      serviceRequired: true,
      moduleLoadProtection: true,
      memoryOnlyInjectionProtection: false,
      threatModel: 'monitors executable/module paths of game processes launched from protected roots; does not claim kernel or memory-only injection coverage',
    };
  }

  _set(next) {
    this.state = { ...this.state, ...next, timestamp: Date.now() };
    return { ...this.state };
  }

  getCachedStatus() { return { ...this.state }; }

  _rootsEnv() {
    return Buffer.from(JSON.stringify(this.roots), 'utf8').toString('base64');
  }

  _runHelper(mode, { pid = 0, expectedPath = '' } = {}) {
    if (this.platform !== 'win32') {
      return Promise.reject(Object.assign(new Error('runtime process guard requires Windows'), { code: 'RUNTIME_PROCESS_WINDOWS_REQUIRED' }));
    }
    const args = ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'RemoteSigned', '-File', this.helper, '-Mode', mode];
    if (mode === 'Terminate') args.push('-ProcessId', String(pid), '-ExpectedPath', expectedPath);
    return new Promise((resolve, reject) => {
      const env = { ...process.env, MALGUARD_RUNTIME_ROOTS_B64: this._rootsEnv() };
      const child = spawn('powershell.exe', args, { shell: false, windowsHide: true, env, stdio: ['ignore', 'pipe', 'pipe'] });
      const stdout = [];
      const stderr = [];
      let total = 0;
      let settled = false;
      const rejectOnce = error => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        try { child.kill(); } catch (_) {}
        reject(error);
      };
      child.stdout.on('data', chunk => {
        total += chunk.length;
        if (total > 1024 * 1024) return rejectOnce(Object.assign(new Error('runtime helper output too large'), { code: 'RUNTIME_HELPER_OUTPUT_TOO_LARGE' }));
        stdout.push(chunk);
      });
      child.stderr.on('data', chunk => { if (Buffer.concat(stderr).length < 128 * 1024) stderr.push(chunk); });
      const timer = setTimeout(() => rejectOnce(Object.assign(new Error('runtime helper timeout'), { code: 'RUNTIME_HELPER_TIMEOUT' })), 8000);
      child.once('error', error => rejectOnce(Object.assign(error, { code: error.code || 'RUNTIME_HELPER_LAUNCH_FAILED' })));
      child.once('exit', code => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (code !== 0) {
          const error = new Error(Buffer.concat(stderr).toString('utf8').trim() || `runtime helper exited ${code}`);
          error.code = 'RUNTIME_HELPER_FAILED';
          return reject(error);
        }
        try {
          const parsed = JSON.parse(Buffer.concat(stdout).toString('utf8').replace(/^\uFEFF/, '').trim());
          if (!parsed || parsed.ok !== true) throw Object.assign(new Error('invalid runtime helper response'), { code: 'RUNTIME_HELPER_INVALID_RESPONSE' });
          resolve(parsed);
        } catch (error) { reject(error); }
      });
    });
  }

  _insideProtectedRoot(filePath) {
    try { return this.roots.some(root => isWithin(filePath, root)); } catch (_) { return false; }
  }

  _isRuntimeCode(filePath) {
    return RUNTIME_CODE_EXTENSIONS.has(path.extname(String(filePath || '')).toLowerCase());
  }

  _isTrustedSystemLocation(filePath) {
    const candidates = [process.env.SystemRoot, process.env.ProgramFiles, process.env['ProgramFiles(x86)'], process.env.ProgramW6432]
      .filter(Boolean)
      .map(value => path.resolve(value));
    try { return candidates.some(root => isWithin(filePath, root)); } catch (_) { return false; }
  }

  async _fileCacheKey(filePath) {
    try {
      const stat = await fs.promises.stat(filePath);
      return `${path.resolve(filePath).toLowerCase()}|${stat.size}|${stat.mtimeMs}`;
    } catch (_) {
      return `${path.resolve(filePath).toLowerCase()}|missing`;
    }
  }

  async _emitIncident({ processInfo, modulePath, verdict, reason, action }) {
    const incident = {
      schemaVersion: '1.0.0',
      incidentId: crypto.randomUUID(),
      modName: processInfo && processInfo.name ? String(processInfo.name) : 'Protected game process',
      responsibleFile: path.basename(modulePath || (processInfo && processInfo.path) || 'unknown'),
      verdict,
      reason,
      action,
      timestamp: Date.now(),
      source: 'runtime-game-process-guard',
    };
    if (this.onIncident) await this.onIncident(incident);
    this._set({ lastIncident: incident });
    return incident;
  }

  async _terminateForViolation(processInfo, modulePath, verdict, reason) {
    const incident = await this._emitIncident({ processInfo, modulePath, verdict, reason, action: 'terminate_game_process' });
    const result = await this.terminateProcess(processInfo.pid, processInfo.path);
    if (!result || result.terminated !== true) throw Object.assign(new Error('process termination was not confirmed'), { code: 'RUNTIME_TERMINATION_UNCONFIRMED' });
    this._set({ lastAction: 'terminated_game_process', lastIncident: incident });
    return { terminated: true, incident };
  }

  async _inspectExternalModule(processInfo, modulePath) {
    if (!this._isRuntimeCode(modulePath) || this._insideProtectedRoot(modulePath) || this._isTrustedSystemLocation(modulePath)) return null;
    const key = await this._fileCacheKey(modulePath);
    if (this.externalCache.get(modulePath) === key) return null;
    let scanResult;
    try { scanResult = await this.scanner(modulePath, { runtimeModule: true, pid: processInfo.pid, processPath: processInfo.path }); }
    catch (_) { scanResult = { verdict: 'INCONCLUSIVE', reasons: ['runtime_module_scan_error'] }; }
    const verdict = normalizeVerdict(scanResult);
    if (verdict === 'SAFE') {
      this.externalCache.set(modulePath, key);
      return null;
    }
    return this._terminateForViolation(processInfo, modulePath, verdict, `untrusted external runtime module: ${verdict.toLowerCase()}`);
  }

  async _inspectProcess(processInfo) {
    if (!processInfo || !Number.isInteger(processInfo.pid) || typeof processInfo.path !== 'string' || !this._insideProtectedRoot(processInfo.path)) return { ignored: true };
    if (processInfo.moduleEnumerationOk !== true) {
      throw Object.assign(new Error('module enumeration failed for protected game process'), { code: 'RUNTIME_MODULE_ENUMERATION_FAILED' });
    }

    const loaded = [processInfo.path, ...(Array.isArray(processInfo.modules) ? processInfo.modules : [])];
    const seen = new Set();
    for (const candidate of loaded) {
      if (typeof candidate !== 'string' || !candidate.trim()) continue;
      const resolved = path.resolve(candidate);
      const key = this.platform === 'win32' ? resolved.toLowerCase() : resolved;
      if (seen.has(key) || !this._isRuntimeCode(resolved)) continue;
      seen.add(key);
      if (this._insideProtectedRoot(resolved)) {
        const trusted = await this.trustedPath(resolved);
        if (!trusted) return this._terminateForViolation(processInfo, resolved, 'INCONCLUSIVE', 'loaded code from protected game root is not in the current trusted identity set');
      } else {
        const result = await this._inspectExternalModule(processInfo, resolved);
        if (result && result.terminated) return result;
      }
    }
    return { ok: true };
  }

  async poll() {
    if (!this.active) return this.getCachedStatus();
    try {
      const snapshot = await this.snapshotProvider();
      const processes = snapshot && Array.isArray(snapshot.processes) ? snapshot.processes : [];
      if (snapshot && snapshot.truncated === true) throw Object.assign(new Error('runtime process snapshot truncated'), { code: 'RUNTIME_SNAPSHOT_TRUNCATED' });
      for (const processInfo of processes) await this._inspectProcess(processInfo);
      return this._set({ ok: true, active: true, healthy: true, monitoredProcesses: processes.length, state: 'healthy', reason: 'runtime_process_monitoring_active', lastError:null });
    } catch (error) {
      const detail = String(error && error.message ? error.message : '').slice(0, 2048);
      return this._set({ ok: false, active: true, healthy: false, state: 'degraded', reason: error && error.code ? error.code : 'RUNTIME_PROCESS_MONITOR_FAILED', lastError:detail || null });
    }
  }

  async start() {
    if (this.active && this.state.healthy) return { ...this.state, alreadyActive: true };
    if (this.platform !== 'win32') return this._set({ ok: false, active: false, healthy: false, state: 'blocked', reason: 'RUNTIME_PROCESS_WINDOWS_REQUIRED' });
    if (!this.serviceMode) return this._set({ ok: false, active: false, healthy: false, state: 'blocked', reason: 'RUNTIME_PROCESS_SERVICE_REQUIRED' });
    this.active = true;
    const first = await this.poll();
    if (!first.ok) { this.active = false; return this._set({ active: false, healthy: false }); }
    this.timer = setInterval(() => { this.poll().catch(() => {}); }, this.intervalMs);
    if (this.timer && typeof this.timer.unref === 'function') this.timer.unref();
    return this.getCachedStatus();
  }

  async stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    this.active = false;
    return this._set({ ok: true, active: false, healthy: false, monitoredProcesses: 0, state: 'stopped', reason: 'requested' });
  }

  async status({ refresh = false } = {}) { return refresh && this.active ? this.poll() : this.getCachedStatus(); }
}

module.exports = { RuntimeGameProcessGuard, RUNTIME_CODE_EXTENSIONS };