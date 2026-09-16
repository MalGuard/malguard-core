'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const SCHEMA_VERSION = 1;
const SHA256_RE = /^[a-f0-9]{64}$/;

function defaultCachePath() {
  const base = process.platform === 'win32'
    ? (process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local'))
    : path.join(os.homedir(), '.cache');
  return path.join(base, 'MalGuard', 'threat-intel-cache.json');
}

class ThreatIntelCache {
  constructor(options = {}) {
    this.filePath = path.resolve(options.filePath || defaultCachePath());
    this.maxEntries = Number.isFinite(options.maxEntries) ? Math.max(32, Math.floor(options.maxEntries)) : 5000;
    this.foundTtlMs = Number.isFinite(options.foundTtlMs) ? options.foundTtlMs : 7 * 24 * 60 * 60 * 1000;
    this.notFoundTtlMs = Number.isFinite(options.notFoundTtlMs) ? options.notFoundTtlMs : 6 * 60 * 60 * 1000;
    this.entries = new Map();
    this.loaded = false;
    this.corrupt = false;
  }

  _isValidEntry(entry) {
    return !!entry && typeof entry === 'object' &&
      typeof entry.hash === 'string' && SHA256_RE.test(entry.hash) &&
      (entry.status === 'known_malicious' || entry.status === 'not_found') &&
      Number.isFinite(entry.cachedAt) && Number.isFinite(entry.expiresAt) && entry.expiresAt >= entry.cachedAt;
  }

  async load() {
    if (this.loaded) return { ok: !this.corrupt, corrupt: this.corrupt, entries: this.entries.size };
    this.loaded = true;
    let raw;
    try {
      raw = await fs.promises.readFile(this.filePath, 'utf8');
    } catch (error) {
      if (error && error.code === 'ENOENT') return { ok: true, corrupt: false, entries: 0 };
      this.corrupt = true;
      return { ok: false, corrupt: true, entries: 0, reason: 'read_failed' };
    }
    try {
      const doc = JSON.parse(raw);
      if (!doc || doc.schemaVersion !== SCHEMA_VERSION || !Array.isArray(doc.entries)) throw new Error('schema');
      for (const entry of doc.entries) {
        if (!this._isValidEntry(entry)) throw new Error('invalid_entry');
        this.entries.set(entry.hash, entry);
      }
      this._prune(Date.now());
      return { ok: true, corrupt: false, entries: this.entries.size };
    } catch (_) {
      this.entries.clear();
      this.corrupt = true;
      return { ok: false, corrupt: true, entries: 0, reason: 'invalid_cache' };
    }
  }

  _prune(now) {
    for (const [hash, entry] of this.entries) {
      if (entry.expiresAt <= now) this.entries.delete(hash);
    }
    if (this.entries.size <= this.maxEntries) return;
    const sorted = [...this.entries.values()].sort((a, b) => a.cachedAt - b.cachedAt);
    const remove = this.entries.size - this.maxEntries;
    for (let i = 0; i < remove; i++) this.entries.delete(sorted[i].hash);
  }

  _toEntry(result, now) {
    if (!result || !SHA256_RE.test(String(result.hash || '').toLowerCase())) return null;
    if (result.status !== 'known_malicious' && result.status !== 'not_found') return null;
    const hash = result.hash.toLowerCase();
    const ttl = result.status === 'known_malicious' ? this.foundTtlMs : this.notFoundTtlMs;
    const safeMetadata = result.status === 'known_malicious' ? {
      signature: typeof result.signature === 'string' ? result.signature : null,
      firstSeen: typeof result.firstSeen === 'string' ? result.firstSeen : null,
      lastSeen: typeof result.lastSeen === 'string' ? result.lastSeen : null,
      fileType: typeof result.fileType === 'string' ? result.fileType : null,
      fileName: typeof result.fileName === 'string' ? result.fileName : null,
      fileSize: Number.isSafeInteger(result.fileSize) && result.fileSize >= 0 ? result.fileSize : null,
      tags: Array.isArray(result.tags) ? result.tags.filter(x => typeof x === 'string').slice(0, 32) : [],
      intelligence: result.intelligence && typeof result.intelligence === 'object' ? {
        clamav: typeof result.intelligence.clamav === 'string' ? result.intelligence.clamav : null,
      } : null,
    } : null;
    return {
      hash,
      provider: 'malwarebazaar',
      status: result.status,
      cachedAt: now,
      expiresAt: now + ttl,
      metadata: safeMetadata,
    };
  }

  async get(hash, now = Date.now()) {
    await this.load();
    const normalized = String(hash || '').toLowerCase();
    if (!SHA256_RE.test(normalized)) return null;
    const entry = this.entries.get(normalized);
    if (!entry) return null;
    if (entry.expiresAt <= now) {
      this.entries.delete(normalized);
      return null;
    }
    return JSON.parse(JSON.stringify(entry));
  }

  async put(result, now = Date.now()) {
    await this.load();
    const entry = this._toEntry(result, now);
    if (!entry) return { ok: false, reason: 'non_cacheable_result' };
    this.entries.set(entry.hash, entry);
    this._prune(now);
    return this.save();
  }

  async putMany(results, now = Date.now()) {
    await this.load();
    if (!Array.isArray(results) || results.length < 1) return { ok: true, entries: this.entries.size, added: 0 };
    const pending = [];
    for (const result of results) {
      const entry = this._toEntry(result, now);
      if (!entry) return { ok: false, reason: 'non_cacheable_batch_result', entries: this.entries.size, added: 0 };
      pending.push(entry);
    }
    for (const entry of pending) this.entries.set(entry.hash, entry);
    this._prune(now);
    const saved = await this.save();
    return { ...saved, added: pending.length };
  }

  async save() {
    const dir = path.dirname(this.filePath);
    await fs.promises.mkdir(dir, { recursive: true, mode: 0o700 });
    const entries = [...this.entries.values()].sort((a, b) => b.cachedAt - a.cachedAt);
    const doc = JSON.stringify({ schemaVersion: SCHEMA_VERSION, savedAt: Date.now(), entries }, null, 2);
    const suffix = crypto.randomBytes(8).toString('hex');
    const tmp = this.filePath + '.tmp-' + process.pid + '-' + suffix;
    await fs.promises.writeFile(tmp, doc, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
    await fs.promises.rename(tmp, this.filePath);
    return { ok: true, entries: this.entries.size };
  }

  status() {
    return { loaded: this.loaded, corrupt: this.corrupt, entries: this.entries.size, filePath: this.filePath };
  }
}

module.exports = { ThreatIntelCache, defaultCachePath };
