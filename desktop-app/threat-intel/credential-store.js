'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn } = require('child_process');

function defaultSecretPath() {
  const base = process.platform === 'win32'
    ? (process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local'))
    : path.join(os.homedir(), '.config');
  return path.join(base, 'MalGuard', 'abusech-auth.dpapi');
}

function runPowerShell(script, stdinText = '') {
  return new Promise((resolve, reject) => {
    const child = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script], {
      windowsHide: true,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const stdout = [];
    const stderr = [];
    child.stdout.on('data', chunk => stdout.push(chunk));
    child.stderr.on('data', chunk => stderr.push(chunk));
    child.on('error', reject);
    child.on('close', code => {
      if (code !== 0) {
        const error = new Error('PowerShell credential operation failed');
        error.code = 'CREDENTIAL_POWERSHELL_FAILED';
        error.stderr = Buffer.concat(stderr).toString('utf8').slice(0, 512);
        return reject(error);
      }
      resolve(Buffer.concat(stdout).toString('utf8').trim());
    });
    child.stdin.end(stdinText, 'utf8');
  });
}

class AbuseChCredentialStore {
  constructor(options = {}) {
    this.secretPath = path.resolve(options.secretPath || defaultSecretPath());
    this.env = options.env || process.env;
    this.platform = options.platform || process.platform;
  }

  async getAuthKey() {
    const envKey = this.env.MALGUARD_ABUSECH_AUTH_KEY;
    if (typeof envKey === 'string' && envKey.trim()) return envKey.trim();
    if (this.platform !== 'win32') return null;
    try {
      await fs.promises.access(this.secretPath, fs.constants.R_OK);
    } catch (_) {
      return null;
    }
    const quotedPath = this.secretPath.replace(/'/g, "''");
    const script = [
      "$ErrorActionPreference='Stop'",
      "Add-Type -AssemblyName System.Security",
      `$b=[IO.File]::ReadAllBytes('${quotedPath}')`,
      "$p=[Security.Cryptography.ProtectedData]::Unprotect($b,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)",
      "[Console]::Out.Write([Text.Encoding]::UTF8.GetString($p))",
    ].join(';');
    const secret = await runPowerShell(script);
    return secret || null;
  }

  async setAuthKey(authKey) {
    const secret = String(authKey || '').trim();
    if (secret.length < 16 || secret.length > 512 || /[\r\n\0]/.test(secret)) {
      const error = new Error('Auth key format rejected');
      error.code = 'INVALID_AUTH_KEY';
      throw error;
    }
    if (this.platform !== 'win32') {
      const error = new Error('Persistent secret storage requires Windows DPAPI; use MALGUARD_ABUSECH_AUTH_KEY for development on this platform.');
      error.code = 'DPAPI_UNAVAILABLE';
      throw error;
    }
    await fs.promises.mkdir(path.dirname(this.secretPath), { recursive: true });
    const quotedPath = this.secretPath.replace(/'/g, "''");
    const script = [
      "$ErrorActionPreference='Stop'",
      "Add-Type -AssemblyName System.Security",
      "$s=[Console]::In.ReadToEnd()",
      "$p=[Text.Encoding]::UTF8.GetBytes($s)",
      "$b=[Security.Cryptography.ProtectedData]::Protect($p,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)",
      `[IO.File]::WriteAllBytes('${quotedPath}',$b)`,
    ].join(';');
    await runPowerShell(script, secret);
    return { ok: true, storage: 'windows-dpapi-current-user' };
  }

  async clear() {
    if (this.platform !== 'win32') return { ok: true, removed: false };
    try {
      await fs.promises.unlink(this.secretPath);
      return { ok: true, removed: true };
    } catch (error) {
      if (error && error.code === 'ENOENT') return { ok: true, removed: false };
      throw error;
    }
  }

  async status() {
    if (typeof this.env.MALGUARD_ABUSECH_AUTH_KEY === 'string' && this.env.MALGUARD_ABUSECH_AUTH_KEY.trim()) {
      return { configured: true, source: 'environment' };
    }
    if (this.platform !== 'win32') return { configured: false, source: 'none' };
    try {
      await fs.promises.access(this.secretPath, fs.constants.R_OK);
      return { configured: true, source: 'windows-dpapi-current-user' };
    } catch (_) {
      return { configured: false, source: 'none' };
    }
  }
}

module.exports = { AbuseChCredentialStore, defaultSecretPath };
