'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { webcrypto, createHash } = require('crypto');
const { performance } = require('perf_hooks');
const { runExternalEngines } = require('./multiengine/external-engine-runner.js');

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
      'streaming-static-scanner.js',
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

  // Large-file branch: disk-backed slices, two bounded hashing passes and identity checks.
  // Does NOT claim PE, archive or multi-engine coverage. Never emits SAFE.
  async scanLargeHandle(handle, resolved, initialStat, mode, options = {}) {
    const CHUNK = 4 * 1024 * 1024;
    const SIZE_LIMIT = 1024 * 1024 * 1024;
    const TIME_LIMIT = 10 * 60 * 1000;
    const started = Date.now();
    const signal = options.signal || null;
    const size = initialStat.size;
    if (!Number.isSafeInteger(size) || size < 1 || size > SIZE_LIMIT) {
      return { resultSchemaVersion:'1.0.0', mode, finalVerdict:'inconclusive', hardeningError:'desktop_file_too_large' };
    }
    function assertRunning() {
      if (signal && signal.aborted) {
        const err = new Error('Large-file scan cancelled');
        err.code = 'SCAN_ABORTED';
        throw err;
      }
      if (Date.now() - started > TIME_LIMIT) {
        const err = new Error('Large-file scan exceeded time limit');
        err.code = 'SCAN_TIMEOUT';
        throw err;
      }
    }
    async function readBlock(from, to) {
      assertRunning();
      if (!Number.isSafeInteger(from) || !Number.isSafeInteger(to) ||
          from < 0 || to <= from || to > size || to - from > CHUNK) {
        const error = new Error('Invalid large-file read bounds');
        error.code = 'SCAN_READ_BOUNDS';
        throw error;
      }
      const data = Buffer.allocUnsafe(to - from);
      let offset = 0;
      while (offset < data.length) {
        assertRunning();
        const { bytesRead } = await handle.read(data, offset, data.length - offset, from + offset);
        if (!bytesRead) {
          const error = new Error('File changed or ended during scan');
          error.code = 'SCAN_READ_TRUNCATED';
          throw error;
        }
        offset += bytesRead;
      }
      return data;
    }
    function isSameFile(before, after) {
      return after.isFile() && !after.isSymbolicLink() &&
        before.size === after.size && before.mtimeMs === after.mtimeMs &&
        before.ctimeMs === after.ctimeMs &&
        before.dev === after.dev && before.ino === after.ino;
    }
    const file = {
      name: path.basename(resolved),
      size,
      slice(from, to) {
        return {
          size: to - from,
          async arrayBuffer() {
            const data = await readBlock(from, to);
            return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
          },
        };
      },
    };
    let summary;
    try {
      summary = await this.context.MalGuardStreamingScanner.scan(file, {
        onProgress: typeof options.onProgress === 'function'
          ? (event) => {
              assertRunning();
              if (options.reportMode === 'detailed') options.onProgress(event);
            }
          : undefined,
      });
      assertRunning();
      const midway = await handle.stat();
      if (!isSameFile(initialStat, midway)) {
        return { resultSchemaVersion:'1.0.0', mode, finalVerdict:'inconclusive',
          hardeningError:'desktop_file_changed_during_scan' };
      }

      // Do not trust a file solely on timestamp/size; independently rehash in blocks.
      const verified = createHash('sha256');
      for (let pos = 0; pos < size; pos += CHUNK) {
        verified.update(await readBlock(pos, Math.min(pos + CHUNK, size)));
      }
      if (verified.digest('hex') !== summary.sha256) {
        return { resultSchemaVersion:'1.0.0', mode, finalVerdict:'inconclusive',
          hardeningError:'desktop_file_changed_during_scan' };
      }
      const endHandleStat = await handle.stat();
      const endPathStat = await withTransientIoRetry(() => fs.promises.lstat(resolved));
      if (!isSameFile(initialStat, endHandleStat) || !isSameFile(initialStat, endPathStat)) {
        return { resultSchemaVersion:'1.0.0', mode, finalVerdict:'inconclusive',
          hardeningError:'desktop_file_changed_during_scan' };
      }
      const result = {
        resultSchemaVersion: '1.0.0', mode,
        finalVerdict: summary.finalVerdict,
        streamingResult: JSON.parse(JSON.stringify(summary)),
        contentSha256: summary.sha256,
        sourceIdentity: { sha256: summary.sha256, revalidated: true },
        hardeningError: 'large_file_partial_analyzer_coverage',
        note: 'All bytes checked for supported string indicators; structural and external engines not run. SAFE not possible.',
        multiEngine: { status: 'skipped', reason: 'large_file_unverified_external_engine_support' },
      };
      return this._applyThreatIntel(result, summary.sha256);
    } catch (error) {
      const output = ioFailureResult(error, mode, 'large-file-stream');
      output.hardeningError = error && error.code === 'SCAN_ABORTED'
        ? 'desktop_scan_aborted' : error && error.code === 'SCAN_TIMEOUT'
        ? 'desktop_scan_timeout' : output.hardeningError;
      return output;
    }
  }

  async scanPath(filePath, mode = 'pro', options = {}) {
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
    if (beforePathStat.size > 1024 * 1024 * 1024) {
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

      if (beforeHandleStat.size > 64 * 1024 * 1024) {
        return this.scanLargeHandle(handle, resolved, beforeHandleStat, mode, options);
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

      // Independent engines run against the exact revalidated on-disk target.
      // Missing optional engines degrade coverage but never crash the scan.
      try {
        result.multiEngine = await runExternalEngines(resolved);
        const engines = Array.isArray(result.multiEngine.engines) ? result.multiEngine.engines : [];
        const hardMalicious = engines.some(e => e && e.name === 'clamav' && e.status === 'malicious');
        const defenderDetection = engines.some(e => e && e.name === 'microsoft_defender' && e.status === 'detected_or_error' && e.exitCode !== 0);
        const yaraMatch = engines.some(e => e && e.name === 'yara_x' && e.status === 'matched');
        if (hardMalicious) {
          result.finalVerdict = 'malicious';
          result.reasons = Array.isArray(result.reasons) ? result.reasons : [];
          result.reasons.unshift('Independent antivirus engine reported a malware detection.');
        } else if ((defenderDetection || yaraMatch) && result.finalVerdict === 'safe') {
          result.finalVerdict = 'suspicious';
          result.reasons = Array.isArray(result.reasons) ? result.reasons : [];
          result.reasons.unshift('Independent engine evidence conflicts with a local SAFE result.');
        }
      } catch (error) {
        result.multiEngine = { schemaVersion:'2.0', engineVersion:'2.0.0', engines:[], completed:0, unavailable:['multi_engine_runner'], error:error && error.code || 'multi_engine_failed' };
      }

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
