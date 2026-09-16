'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { SettingsStore } = require('../settings-store.js');

const SELF_HEAL_VERSION = '1.0.0';

function errorCode(error, fallback) {
  return String((error && (error.code || error.message)) || fallback || 'UNKNOWN_ERROR');
}

function atomicWriteJsonSync(filePath, value) {
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const temp = path.join(dir, `.${path.basename(filePath)}.${process.pid}.${crypto.randomUUID()}.tmp`);
  fs.writeFileSync(temp, JSON.stringify(value, null, 2) + '\n', { encoding: 'utf8', flag: 'wx', mode: 0o600 });
  fs.renameSync(temp, filePath);
}

function probeWritableDirectorySync(dir) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const marker = path.join(dir, `.malguard-write-probe-${process.pid}-${crypto.randomUUID()}`);
  fs.writeFileSync(marker, 'ok\n', { encoding: 'utf8', flag: 'wx', mode: 0o600 });
  fs.unlinkSync(marker);
  return true;
}

class SafeSelfHeal {
  constructor({ settingsStore = null } = {}) {
    this.settingsStore = settingsStore || new SettingsStore();
  }

  _readSettings() {
    const file = this.settingsStore.filePath;
    if (!fs.existsSync(file)) return { state: 'missing', config: this.settingsStore.defaults() };
    try {
      const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
      return { state: 'valid', config: this.settingsStore.validate(parsed) };
    } catch (error) {
      return { state: 'corrupt', error, config: this.settingsStore.defaults() };
    }
  }

  repairSync() {
    const startedAt = Date.now();
    const actions = [];
    const blockers = [];
    const settingsFile = this.settingsStore.filePath;
    let settings = this._readSettings();

    if (settings.state === 'corrupt') {
      const backup = `${settingsFile}.corrupt-${Date.now()}`;
      try {
        fs.mkdirSync(path.dirname(settingsFile), { recursive: true, mode: 0o700 });
        fs.renameSync(settingsFile, backup);
        actions.push({ id: 'settings-backup', ok: true, detail: backup });
        settings = { state: 'missing', config: this.settingsStore.defaults() };
      } catch (error) {
        blockers.push({ id: 'settings-corrupt', code: errorCode(error, 'SETTINGS_BACKUP_FAILED') });
      }
    }

    if (settings.state === 'missing' && blockers.length === 0) {
      try {
        const validated = this.settingsStore.validate(settings.config);
        atomicWriteJsonSync(settingsFile, validated);
        settings = { state: 'repaired', config: validated };
        actions.push({ id: 'settings-create', ok: true, detail: settingsFile });
      } catch (error) {
        blockers.push({ id: 'settings-create', code: errorCode(error, 'SETTINGS_CREATE_FAILED') });
      }
    }

    const config = settings.config || this.settingsStore.defaults();
    const directories = [
      { id: 'settings-dir', path: path.dirname(settingsFile) },
      { id: 'quarantine-dir', path: config.quarantineRoot },
      { id: 'staging-dir', path: config.stagingRoot },
      { id: 'sandbox-temp-dir', path: path.join(os.tmpdir(), 'malguard-windows-sandbox') },
    ];

    for (const entry of directories) {
      try {
        probeWritableDirectorySync(entry.path);
        actions.push({ id: entry.id, ok: true, detail: entry.path });
      } catch (error) {
        blockers.push({ id: entry.id, code: errorCode(error, 'DIRECTORY_NOT_WRITABLE'), path: entry.path });
      }
    }

    const ok = blockers.length === 0;
    return Object.freeze({
      selfHealVersion: SELF_HEAL_VERSION,
      ok,
      degraded: !ok,
      repaired: actions.some(action => action.id === 'settings-create' || action.id === 'settings-backup'),
      settingsState: settings.state,
      actions,
      blockers,
      note: 'Self-heal only repairs MalGuard-owned local state. It never enables Windows features, changes OS security policy, bypasses ACLs, or weakens fail-closed controls.',
      durationMs: Date.now() - startedAt,
      timestamp: new Date().toISOString(),
    });
  }
}

module.exports = { SafeSelfHeal, SELF_HEAL_VERSION, atomicWriteJsonSync, probeWritableDirectorySync };
