'use strict';

const { MalwareBazaarClient } = require('./malwarebazaar-client.js');
const { ThreatIntelCache } = require('./cache-store.js');
const { AbuseChCredentialStore } = require('./credential-store.js');

class ThreatIntelService {
  constructor(options = {}) {
    this.credentials = options.credentials || new AbuseChCredentialStore(options.credentialOptions);
    this.cache = options.cache || new ThreatIntelCache(options.cacheOptions);
    this.client = options.client || new MalwareBazaarClient({
      authKeyProvider: () => this.credentials.getAuthKey(),
      fetchImpl: options.fetchImpl,
      timeoutMs: options.timeoutMs,
      maxResponseBytes: options.maxResponseBytes,
    });
    this.recentSyncIntervalMs = Number.isFinite(options.recentSyncIntervalMs)
      ? Math.max(60 * 1000, Math.floor(options.recentSyncIntervalMs))
      : 30 * 60 * 1000;
    this.lastRecentSyncAttemptAt = 0;
    this.lastRecentSync = { status: 'never', count: 0, metadataOnly: true };
    this._recentSyncPromise = null;
  }

  _triggerRecentSyncIfDue(force = false) {
    const now = Date.now();
    if (!force && now - this.lastRecentSyncAttemptAt < this.recentSyncIntervalMs) return this._recentSyncPromise;
    if (this._recentSyncPromise) return this._recentSyncPromise;
    this.lastRecentSyncAttemptAt = now;
    this._recentSyncPromise = this.syncRecent({ selector: '100' })
      .catch(() => ({ provider: 'malwarebazaar', status: 'unavailable', reason: 'recent_sync_exception', count: 0, metadataOnly: true }))
      .finally(() => { this._recentSyncPromise = null; });
    return this._recentSyncPromise;
  }

  async syncRecent(options = {}) {
    const selector = options.selector === 'time' ? 'time' : '100';
    const live = await this.client.listRecent(selector);
    const completedAt = Date.now();
    if (!live || live.status !== 'ok') {
      this.lastRecentSync = {
        status: live && live.status ? live.status : 'unavailable',
        reason: live && live.reason ? live.reason : null,
        count: 0,
        selector,
        completedAt,
        metadataOnly: true,
      };
      return { ...this.lastRecentSync, provider: 'malwarebazaar', source: 'live' };
    }

    const entries = Array.isArray(live.entries) ? live.entries : [];
    const stored = await this.cache.putMany(entries, completedAt);
    if (!stored.ok) {
      this.lastRecentSync = {
        status: 'unavailable',
        reason: stored.reason || 'cache_write_failed',
        count: 0,
        selector,
        completedAt,
        metadataOnly: true,
      };
      return { ...this.lastRecentSync, provider: 'malwarebazaar', source: 'live' };
    }

    this.lastRecentSync = {
      status: 'ok',
      count: entries.length,
      selector,
      completedAt,
      metadataOnly: true,
      samplesDownloaded: false,
      cacheEntries: stored.entries,
    };
    return { ...this.lastRecentSync, provider: 'malwarebazaar', source: 'live' };
  }

  async lookupSha256(hash, options = {}) {
    if (options.syncRecent !== false) this._triggerRecentSyncIfDue(options.forceRecentSync === true);
    const normalized = String(hash || '').trim().toLowerCase();
    const cached = await this.cache.get(normalized);
    if (cached && options.forceRefresh !== true) {
      return this._fromCache(cached);
    }

    const live = await this.client.lookupSha256(normalized);
    if (live.status === 'known_malicious' || live.status === 'not_found') {
      await this.cache.put(live);
      return Object.assign({ source: 'live' }, live);
    }

    // Stale known-malicious cache is intentionally not trusted past TTL; a corrupted or expired
    // local database may not silently manufacture a security verdict. Network failure is exposed
    // as metadata and local static analysis remains the deciding layer.
    return Object.assign({ source: 'live' }, live);
  }

  _fromCache(entry) {
    const base = {
      provider: 'malwarebazaar',
      status: entry.status,
      hash: entry.hash,
      source: 'cache',
      cachedAt: entry.cachedAt,
      expiresAt: entry.expiresAt,
    };
    if (entry.status === 'known_malicious' && entry.metadata) {
      return Object.assign(base, entry.metadata);
    }
    return base;
  }

  async status() {
    const credential = await this.credentials.status();
    await this.cache.load();
    const cache = this.cache.status();
    if (credential.configured) this._triggerRecentSyncIfDue(false);
    return {
      provider: 'malwarebazaar',
      configured: credential.configured,
      credentialSource: credential.source,
      cache: { loaded: cache.loaded, corrupt: cache.corrupt, entries: cache.entries },
      recentFeed: { ...this.lastRecentSync, inFlight: !!this._recentSyncPromise },
    };
  }
}

module.exports = { ThreatIntelService };
