'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const SETTINGS_SCHEMA_VERSION = '2.0.0';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function diagnosticsDefaults() { return { enabled:false, shareRegion:false, installationId:crypto.randomUUID(), lastUploadAt:null, consentUpdatedAt:null, deletionPending:false, country:null, region:null }; }
function diagnostics(input) {
  const d = input || {};
  return { enabled:d.enabled === true && typeof d.consentUpdatedAt === 'string', shareRegion:d.shareRegion === true,
    installationId:UUID.test(d.installationId) ? d.installationId : crypto.randomUUID(),
    lastUploadAt:typeof d.lastUploadAt === 'string' ? d.lastUploadAt : null,
    consentUpdatedAt:typeof d.consentUpdatedAt === 'string' ? d.consentUpdatedAt : null,
    deletionPending:d.deletionPending === true,
    country:typeof d.country === 'string' && /^[A-Z]{2}$/.test(d.country) ? d.country : null,
    region:typeof d.region === 'string' && /^[\p{L} .'-]{1,64}$/u.test(d.region) ? d.region : null };
}

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
      diagnostics: diagnosticsDefaults(),
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
      diagnostics: diagnostics(input.schemaVersion && input.schemaVersion !== SETTINGS_SCHEMA_VERSION ? null : input.diagnostics),
    };
  }

  loadSync() {
    try {
      const raw = fs.readFileSync(this.filePath, 'utf8');
      const parsed = JSON.parse(raw);
      if (!['1.0.0', SETTINGS_SCHEMA_VERSION].includes(parsed.schemaVersion)) return this.defaults();
      const migrated = this.validate(parsed);
      if (parsed.schemaVersion !== SETTINGS_SCHEMA_VERSION || !UUID.test(parsed.diagnostics?.installationId)) {
        try { this.saveSync(migrated); } catch (_) { migrated.diagnostics.enabled = false; }
      }
      return migrated;
    } catch (_) {
      return this.defaults();
    }
  }

  saveSync(input) {
    const validated = this.validate(input);
    fs.mkdirSync(path.dirname(this.filePath), { recursive:true, mode:0o700 });
    const temp = `${this.filePath}.${crypto.randomUUID()}.tmp`;
    fs.writeFileSync(temp, JSON.stringify(validated, null, 2), { encoding:'utf8', flag:'wx', mode:0o600 });
    fs.renameSync(temp, this.filePath);
    return validated;
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
