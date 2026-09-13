'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const SETTINGS_SCHEMA_VERSION = '1.0.0';

function uniquePaths(values) {
  const seen = new Set();
  const out = [];
  for (const value of values || []) {
    if (typeof value !== 'string' || !value.trim()) continue;
    const resolved = path.resolve(value.trim());
    const key = process.platform === 'win32' ? resolved.toLowerCase() : resolved;
    if (!seen.has(key)) { seen.add(key); out.push(resolved); }
  }
  return out;
}

function isInside(child, parent) {
  const c = path.resolve(child);
  const p = path.resolve(parent);
  const rel = path.relative(p, c);
  return rel === '' || (!rel.startsWith('..' + path.sep) && rel !== '..' && !path.isAbsolute(rel));
}

class SettingsStore {
  constructor(filePath = null) {
    const home = os.homedir();
    const base = process.env.LOCALAPPDATA
      ? path.join(process.env.LOCALAPPDATA, 'MalGuard')
      : path.join(home, '.malguard');
    this.filePath = path.resolve(filePath || path.join(base, 'settings.json'));
  }

  defaults() {
    const home = os.homedir();
    return {
      schemaVersion: SETTINGS_SCHEMA_VERSION,
      watchRoots: [],
      quarantineRoot: path.resolve(path.join(home, '.malguard', 'quarantine')),
      stagingRoot: path.resolve(path.join(home, '.malguard', 'staging')),
      updatedAt: 0,
    };
  }

  validate(input) {
    if (!input || typeof input !== 'object') throw Object.assign(new TypeError('settings object required'), { code: 'SETTINGS_REQUIRED' });
    const watchRoots = uniquePaths(input.watchRoots);
    if (watchRoots.length > 16) throw Object.assign(new Error('too many watch roots'), { code: 'TOO_MANY_WATCH_ROOTS' });
    const quarantineRoot = path.resolve(String(input.quarantineRoot || this.defaults().quarantineRoot));
    const stagingRoot = path.resolve(String(input.stagingRoot || this.defaults().stagingRoot));

    for (const root of watchRoots) {
      if (isInside(quarantineRoot, root) || isInside(stagingRoot, root)) {
        throw Object.assign(new Error('quarantine/staging roots must be outside protected game roots'), { code: 'AUXILIARY_ROOT_INSIDE_WATCH_ROOT' });
      }
    }
    if (isInside(quarantineRoot, stagingRoot) || isInside(stagingRoot, quarantineRoot)) {
      throw Object.assign(new Error('quarantine and staging roots must not overlap'), { code: 'AUXILIARY_ROOTS_OVERLAP' });
    }

    return {
      schemaVersion: SETTINGS_SCHEMA_VERSION,
      watchRoots,
      quarantineRoot,
      stagingRoot,
      updatedAt: Date.now(),
    };
  }

  loadSync() {
    try {
      const raw = fs.readFileSync(this.filePath, 'utf8');
      const parsed = JSON.parse(raw);
      if (parsed.schemaVersion !== SETTINGS_SCHEMA_VERSION) return this.defaults();
      return this.validate(parsed);
    } catch (_) {
      return this.defaults();
    }
  }

  async save(input) {
    const validated = this.validate(input);
    await fs.promises.mkdir(path.dirname(this.filePath), { recursive: true, mode: 0o700 });
    const temp = `${this.filePath}.${crypto.randomUUID()}.tmp`;
    await fs.promises.writeFile(temp, JSON.stringify(validated, null, 2), { encoding: 'utf8', flag: 'wx', mode: 0o600 });
    await fs.promises.rename(temp, this.filePath);
    return validated;
  }
}

module.exports = { SettingsStore, SETTINGS_SCHEMA_VERSION, isInside };
