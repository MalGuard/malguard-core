'use strict';

const ENDPOINT = 'https://urlhaus-api.abuse.ch/v1/url/';
const SOURCE = 'https://urlhaus.abuse.ch/';

function result(status, reason, metadata = {}) {
  return { provider: 'urlhaus', source: SOURCE, status, ...(reason ? { reason } : {}), ...metadata };
}

// URLhaus IDs may be decimal strings or safe positive integers, never arrays or objects.
function validRecordId(id) {
  return (typeof id === 'string' && /^\d+$/.test(id)) ||
    (typeof id === 'number' && Number.isSafeInteger(id) && id > 0);
}

// A regex alone accepts impossible months, days and times; round-trip through UTC.
function validUpstreamTimestamp(value) {
  if (typeof value !== 'string') return false;
  const match = /^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})( UTC)?$/.exec(value);
  if (!match) return false;
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number);
  if (year === 0) return false;
  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  date.setUTCHours(hour, minute, second, 0);
  return date.getUTCFullYear() === year && date.getUTCMonth() === month - 1 &&
    date.getUTCDate() === day && date.getUTCHours() === hour &&
    date.getUTCMinutes() === minute && date.getUTCSeconds() === second;
}

class UrlhausClient {
  constructor(options = {}) {
    this.fetchImpl = options.fetchImpl || globalThis.fetch;
    this.authKeyProvider = options.authKeyProvider || (async () => null);
    this.timeoutMs = Number.isFinite(options.timeoutMs)
      ? Math.min(30000, Math.max(1, options.timeoutMs)) : 8000;
    this.maxResponseBytes = Number.isFinite(options.maxResponseBytes)
      ? Math.min(1024 * 1024, Math.max(1, options.maxResponseBytes)) : 256 * 1024;
  }

  async lookupUrl(indicator, options = {}) {
    // Consent is required per lookup, even when the caller holds a configured key.
    if (options.consent !== true) return result('not_checked', 'consent_required');
    if (typeof indicator !== 'string' || indicator.length > 8192) {
      return result('not_checked', 'invalid_url');
    }
    let parsed;
    try { parsed = new URL(indicator); } catch (_) { return result('not_checked', 'invalid_url'); }
    if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password ||
        indicator !== indicator.trim() || /[\u0000-\u0020\u007f]/.test(indicator)) {
      return result('not_checked', 'invalid_url');
    }
    if (typeof this.fetchImpl !== 'function') return result('unavailable', 'fetch_unavailable');

    const controller = new AbortController();
    let timer;
    const deadline = new Promise((resolve) => {
      timer = setTimeout(() => {
        controller.abort();
        resolve(result('unavailable', 'timeout'));
      }, this.timeoutMs);
    });
    try {
      return await Promise.race([this._lookup(indicator, controller.signal), deadline]);
    } finally {
      clearTimeout(timer);
      controller.abort();
    }
  }

  async _lookup(indicator, signal) {
    let key;
    try { key = await this.authKeyProvider(); } catch (_) {
      return result('unavailable', 'credential_read_failed');
    }
    if (signal.aborted) return result('unavailable', 'timeout');
    if (typeof key !== 'string' || !key.trim()) return result('unavailable', 'missing_credentials');
    let response;
    try {
      response = await this.fetchImpl(ENDPOINT, {
        method: 'POST',
        redirect: 'error',
        headers: { 'Auth-Key': key.trim(), Accept: 'application/json',
          'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ url: indicator }).toString(),
        signal,
      });
    } catch (_) {
      return result('unavailable', signal.aborted ? 'timeout' : 'network_error');
    }
    if (!response || !response.ok) {
      if (response && response.body) {
        try { await response.body.cancel(); } catch (_) { /* Best-effort cleanup. */ }
      }
      return result('unavailable', response && Number.isInteger(response.status)
        ? 'http_' + response.status : 'http_unknown');
    }

    // Do not call response.text(): enforce the byte bound while reading, not afterward.
    if (!response.body || typeof response.body.getReader !== 'function') {
      return result('invalid_response', 'missing_body');
    }
    const reader = response.body.getReader();
    const cancelReader = () => { Promise.resolve(reader.cancel()).catch(() => {}); };
    signal.addEventListener('abort', cancelReader, { once: true });
    if (signal.aborted) cancelReader();
    const chunks = [];
    let size = 0;
    let text;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > this.maxResponseBytes) return result('invalid_response', 'response_too_large');
        chunks.push(Buffer.from(value));
      }
      if (signal.aborted) return result('unavailable', 'timeout');
      text = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks));
    } catch (_) {
      return result(signal.aborted ? 'unavailable' : 'invalid_response',
        signal.aborted ? 'timeout' : 'body_read_failed');
    } finally {
      // Cancellation must not extend the lookup deadline on a stalled stream.
      signal.removeEventListener('abort', cancelReader);
      cancelReader();
      reader.releaseLock();
    }
    let payload;
    try { payload = JSON.parse(text); } catch (_) { return result('invalid_response', 'invalid_json'); }
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
      return result('invalid_response', 'unexpected_shape');
    }
    if (payload.query_status === 'no_results') {
      // An upstream contradiction must never be presented as a negative lookup.
      const matchedFields = ['id', 'url', 'url_status', 'threat', 'date_added'];
      if (matchedFields.some((field) => Object.hasOwn(payload, field))) {
        return result('invalid_response', 'unexpected_shape');
      }
      return result('no_match');
    }
    if (['no_api_key', 'invalid_api_key', 'user_blacklisted'].includes(payload.query_status)) {
      return result('unavailable', 'authentication_failed');
    }
    if (payload.query_status !== 'ok' || payload.url !== indicator ||
        !['online', 'offline', 'unknown'].includes(payload.url_status) ||
        payload.threat !== 'malware_download' || !validRecordId(payload.id)) {
      return result('invalid_response', 'unexpected_shape');
    }
    // Return only allowlisted metadata. Never echo submitted URLs, keys, or raw responses.
    return result('matched', null, {
      reference: SOURCE + 'url/' + payload.id + '/',
      urlStatus: payload.url_status,
      threat: payload.threat,
      upstreamTimestamp: validUpstreamTimestamp(payload.date_added) ? payload.date_added : null,
    });
  }
}

module.exports = { UrlhausClient };
