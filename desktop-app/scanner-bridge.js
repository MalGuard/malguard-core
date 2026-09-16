'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { webcrypto, createHash } = require('crypto');
const { performance } = require('perf_hooks');

const ROOT = path.resolve(__dirname, '..');
const TRANSIENT_IO_CODES = new Set(['EBUSY', 'ETXTBSY', 'EAGAIN']);

function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

async function withTransientIoRetry(fn, attempts = 3) {
  let lastError;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try { return await fn(); }
    catch (error) {
      lastError = error;
      if (!error || !TRANSIENT_IO_CODES.has(error.code) || attempt >= attempts) throw error;
      await sleep(35 * attempt);
    }
  }
  throw lastError;
}

function ioFailureResult(error, mode, phase) {
  const code = error && error.code;
  let hardeningError = 'desktop_file_io_failed';
  if (code === 'ENOENT') hardeningError = 'desktop_file_not_found';
  else if (code === 'EACCES' || code === 'EPERM') hardeningError = 'desktop_file_access_denied';
  else if (TRANSIENT_IO_CODES.has(code)) hardeningError = 'desktop_file_busy';
  return {
    resultSchemaVersion: '1.0.0',
    finalVerdict: 'inconclusive',
    hardeningError,
    mode,
    io: { phase, code: code || 'UNKNOWN_IO_ERROR', retryable: TRANSIENT_IO_CODES.has(code) },
    note: 'MalGuard could not prove the file contents at this moment, so the scan remains fail-closed instead of crashing or claiming success.',
  };
}

class FileLike {
  constructor(name, bytes) {
    this.name = String(name || 'sample.bin');
    this._bytes = Buffer.from(bytes || []);
    this.size = this._bytes.length;
  }
  async arrayBuffer() {
    return this._bytes.buffer.slice(this._bytes.byteOffset, this._bytes.byteOffset + this._bytes.byteLength);
  }
  slice(start, end) {
    return new FileLike(this.name, this._bytes.subarray(start || 0, end == null ? this._bytes.length : end));
  }
}

function makeLocalFetch() {
  return async function localFetch(url) {
    const target = String(url || '');
    if (target === 'rules.json' || target.endsWith('/rules.json')) {
      const data = JSON.parse(await fs.promises.readFile(path.join(ROOT, 'rules.json'), 'utf8'));
      return {
        ok: true,
        status: 200,
        async json() { return data; },
        async text() { return JSON.stringify(data); },
      };
    }
    return {
      ok: false,
      status: 503,
      async json() { return {}; },
      async text() { return JSON.stringify({ query_status: 'unavailable' }); },
    };
  };
}

function makeContext() {
  const context = {
    console,
    TextDecoder,
    TextEncoder,
    crypto: webcrypto,
    performance,
    setTimeout,
    clearTimeout,
    AbortController,
    ReadableStream: globalThis.ReadableStream,
    DecompressionStream: globalThis.DecompressionStream,
    fetch: makeLocalFetch(),
    window: null,
  };
  context.window = context;
  vm.createContext(context);
  return context;
}

function load(context, filename) {
  const source = fs.readFileSync(path.join(ROOT, filename), 'utf8');
  vm.runInContext(source, context, { filename });
}

class ScannerBridge {
  constructor(options = {}) {
    this.threatIntel = options.threatIntel || null;
    this.context = makeContext();
    for (const file of [
      'malguard-contract.js',
      'engine.js',
      'multilayer.js',
      'gta-mod-detector.js',
      'archive-inspector.js',
      'archive-entry-reader.js',
      'script-analyzer.js',
      'app.js',
    ]) load(this.context, file);
  }

  async scanBuffer(name, bytes, mode = 'pro') {
    const inputBytes = Buffer.from(bytes || []);
    const contentSha256 = createHash('sha256').update(inputBytes).digest('hex');
    const file = new FileLike(name, inputBytes);
    let result;
    try {
      result = await this.context.scanFileWithMode(file, mode);
    } catch (error) {
      return {
        resultSchemaVersion: '1.0.0',
        mode,
        finalVerdict: 'inconclusive',
        hardeningError: 'desktop_bridge_error',
        note: error && error.message ? error.message : 'scanner bridge failed closed',
      };
    }
    result = JSON.parse(JSON.stringify(result));
    result.contentSha256 = contentSha256;
    return this._applyThreatIntel(result, contentSha256);
  }

  async _applyThreatIntel(result, sha256) {
    if (!this.threatIntel || typeof this.threatIntel.lookupSha256 !== 'function') {
      result.threatIntel = { provider: 'malwarebazaar', status: 'disabled', source: 'none' };
      return result;
    }

    let intel;
    try {
      intel = await this.threatIntel.lookupSha256(sha256);
    } catch (_) {
      intel = { provider: 'malwarebazaar', status: 'unavailable', reason: 'service_exception', hash: sha256, source: 'local' };
    }
    result.threatIntel = intel;

    if (intel && intel.status === 'known_malicious') {
      result.finalVerdict = 'malicious';
      result.reputationOverride = 'malwarebazaar_exact_sha256';
      const signature = intel.signature ? ` (${intel.signature})` : '';
      const reason = `MalwareBazaar exact SHA-256 match${signature}; the file is known malware in the reputation source.`;
      if (Array.isArray(result.reasons)) result.reasons.unshift(reason);
      else result.reasons = [reason];
      result.reputationEvidence = Array.isArray(result.reputationEvidence) ? result.reputationEvidence : [];
      result.reputationEvidence.push({
        provider: 'MalwareBazaar',
        rule: 'MALWAREBAZAAR-EXACT-SHA256',
        severity: 'critical',
        confidence: 'high',
        hash: sha256,
        signature: intel.signature || null,
        source: intel.source || 'live',
      });
    }
    return result;
  }

  async scanPath(filePath, mode = 'pro') {
    const resolved = path.resolve(filePath);
    let beforePathStat;
    try { beforePathStat = await withTransientIoRetry(() => fs.promises.lstat(resolved)); }
    catch (error) { return ioFailureResult(error, mode, 'lstat-before-open'); }

    if (beforePathStat.isSymbolicLink()) {
      const error = new Error('scan target may not be a symbolic link');
      error.code = 'SCAN_TARGET_SYMLINK';
      throw error;
    }
    if (!beforePathStat.isFile()) {
      const error = new Error('scan target must be a file');
      error.code = 'SCAN_TARGET_NOT_FILE';
      throw error;
    }
    if (beforePathStat.size > 64 * 1024 * 1024) {
      return { resultSchemaVersion: '1.0.0', finalVerdict: 'inconclusive', hardeningError: 'desktop_file_too_large', mode };
    }

    const flags = fs.constants.O_RDONLY | (Number.isInteger(fs.constants.O_NOFOLLOW) ? fs.constants.O_NOFOLLOW : 0);
    let handle;
    try {
      try { handle = await withTransientIoRetry(() => fs.promises.open(resolved, flags)); }
      catch (error) { return ioFailureResult(error, mode, 'open'); }

      let beforeHandleStat;
      try { beforeHandleStat = await handle.stat(); }
      catch (error) { return ioFailureResult(error, mode, 'fstat-before-read'); }
      if (!beforeHandleStat.isFile() || beforeHandleStat.size !== beforePathStat.size) {
        return { resultSchemaVersion: '1.0.0', finalVerdict: 'inconclusive', hardeningError: 'desktop_file_identity_changed_before_read', mode };
      }

      let bytes;
      try { bytes = await handle.readFile(); }
      catch (error) { return ioFailureResult(error, mode, 'read'); }
      let afterHandleStat;
      try { afterHandleStat = await handle.stat(); }
      catch (error) { return ioFailureResult(error, mode, 'fstat-after-read'); }
      if (bytes.length !== beforeHandleStat.size || afterHandleStat.size !== beforeHandleStat.size || afterHandleStat.mtimeMs !== beforeHandleStat.mtimeMs) {
        return { resultSchemaVersion: '1.0.0', finalVerdict: 'inconclusive', hardeningError: 'desktop_file_changed_during_read', mode };
      }

      const scannedIdentity = createHash('sha256').update(bytes).digest('hex');
      const result = await this.scanBuffer(path.basename(resolved), bytes, mode);

      let currentStat;
      try { currentStat = await withTransientIoRetry(() => fs.promises.lstat(resolved)); }
      catch (error) {
        const io = ioFailureResult(error, mode, 'lstat-after-scan');
        io.scannerResult = result;
        return io;
      }
      if (!currentStat.isFile() || currentStat.isSymbolicLink() || currentStat.size > 64 * 1024 * 1024) {
        return { resultSchemaVersion: '1.0.0', finalVerdict: 'inconclusive', hardeningError: 'desktop_file_identity_changed_after_scan', mode, scannerResult: result };
      }
      let currentBytes;
      try { currentBytes = await withTransientIoRetry(() => fs.promises.readFile(resolved)); }
      catch (error) {
        const io = ioFailureResult(error, mode, 'revalidate-read');
        io.scannerResult = result;
        return io;
      }
      const currentIdentity = createHash('sha256').update(currentBytes).digest('hex');
      if (currentIdentity !== scannedIdentity) {
        return {
          resultSchemaVersion: '1.0.0',
          finalVerdict: 'inconclusive',
          hardeningError: 'desktop_file_changed_during_scan',
          mode,
          scannerResult: result,
          sourceIdentity: { scannedSha256: scannedIdentity, currentSha256: currentIdentity },
        };
      }
      result.sourceIdentity = { sha256: scannedIdentity, revalidated: true };
      return result;
    } finally {
      if (handle) await handle.close().catch(() => {});
    }
  }
}

module.exports = { ScannerBridge, FileLike, withTransientIoRetry, ioFailureResult };
