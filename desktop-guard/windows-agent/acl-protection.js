'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const { normalizeAbsolute, assertWithinAny } = require('./path-guard.js');

const ACL_GATE_VERSION = '0.1.0';

class ProtectedFolderAclGate {
  constructor({ roots, stateRoot, timeoutMs = 12000 } = {}) {
    if (!Array.isArray(roots) || !roots.length) throw new TypeError('roots required');
    this.roots = roots.map(normalizeAbsolute);
    this.stateRoot = normalizeAbsolute(stateRoot);
    this.timeoutMs = Math.max(3000, Number(timeoutMs) || 12000);
    this.helper = path.join(__dirname, 'windows-tools', 'acl-helper.ps1');
  }

  capabilities() {
    return {
      version: ACL_GATE_VERSION,
      platform: process.platform,
      supported: process.platform === 'win32',
      threatModel: 'blocks unprivileged interactive writers; administrator/kernel compromise is out of scope',
    };
  }

  _backupPath(root) {
    const key = crypto.createHash('sha256').update(root.toLowerCase()).digest('hex').slice(0, 24);
    return path.join(this.stateRoot, 'acl-backups', `${key}.sddl`);
  }

  async _run(mode, root) {
    if (process.platform !== 'win32') {
      const error = new Error('Windows ACL access gate is unavailable on this platform');
      error.code = 'ACL_GATE_UNSUPPORTED_PLATFORM';
      throw error;
    }
    const target = assertWithinAny(root, this.roots);
    const backup = this._backupPath(target);
    await fs.promises.mkdir(path.dirname(backup), { recursive: true });
    const args = ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'RemoteSigned', '-File', this.helper, '-Mode', mode, '-Target', target];
    if (mode !== 'Status') args.push('-Backup', backup);

    return new Promise((resolve, reject) => {
      const child = spawn('powershell.exe', args, { shell: false, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
      const stdout = [];
      const stderr = [];
      let total = 0;
      let settled = false;
      const finishReject = (error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        try { child.kill(); } catch (_) {}
        reject(error);
      };
      child.stdout.on('data', chunk => {
        total += chunk.length;
        if (total > 256 * 1024) return finishReject(Object.assign(new Error('ACL helper output exceeded cap'), { code: 'ACL_GATE_OUTPUT_TOO_LARGE' }));
        stdout.push(chunk);
      });
      child.stderr.on('data', chunk => { if (stderr.reduce((n,b)=>n+b.length,0) < 64 * 1024) stderr.push(chunk); });
      const timer = setTimeout(() => finishReject(Object.assign(new Error('ACL helper timeout'), { code: 'ACL_GATE_TIMEOUT' })), this.timeoutMs);
      child.once('error', error => finishReject(Object.assign(error, { code: error.code || 'ACL_GATE_LAUNCH_FAILED' })));
      child.once('exit', code => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (code !== 0) {
          const error = new Error(Buffer.concat(stderr).toString('utf8').trim() || `ACL helper exited ${code}`);
          error.code = 'ACL_GATE_HELPER_FAILED';
          return reject(error);
        }
        try {
          const parsed = JSON.parse(Buffer.concat(stdout).toString('utf8').replace(/^\uFEFF/, '').trim());
          if (!parsed || parsed.ok !== true || path.resolve(parsed.target) !== path.resolve(target)) {
            throw Object.assign(new Error('invalid ACL helper response'), { code: 'ACL_GATE_INVALID_RESPONSE' });
          }
          resolve(parsed);
        } catch (error) { reject(error); }
      });
    });
  }

  async protectAll() {
    const results = [];
    for (const root of this.roots) results.push(await this._run('Protect', root));
    return { ok: results.every(x => x.protected === true), results };
  }

  async restoreAll() {
    const results = [];
    for (const root of this.roots) results.push(await this._run('Restore', root));
    return { ok: true, results };
  }

  async status() {
    if (process.platform !== 'win32') return { ok: false, supported: false, code: 'ACL_GATE_UNSUPPORTED_PLATFORM', roots: this.roots };
    const results = [];
    for (const root of this.roots) results.push(await this._run('Status', root));
    return { ok: true, supported: true, protected: results.length > 0 && results.every(x => x.protected === true), results };
  }
}

module.exports = { ProtectedFolderAclGate, ACL_GATE_VERSION };
