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
  }

  async lookupSha256(hash, options = {}) {
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
    return {
      provider: 'malwarebazaar',
      configured: credential.configured,
      credentialSource: credential.source,
      cache: { loaded: cache.loaded, corrupt: cache.corrupt, entries: cache.entries },
    };
  }
}

module.exports = { ThreatIntelService };
