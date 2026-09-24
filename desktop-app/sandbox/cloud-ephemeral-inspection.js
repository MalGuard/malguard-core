'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DEFAULT_ENDPOINT = 'https://malguard-core-sandbox.vercel.app/api/cloud-sandbox-file-inspection';
const MAX_CLOUD_INSPECTION_BYTES = 8 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 45_000;

async function readStableFile(filePath, maxBytes = MAX_CLOUD_INSPECTION_BYTES) {
  const resolved = path.resolve(filePath);
  const before = await fs.promises.lstat(resolved);
  if (!before.isFile() || before.isSymbolicLink()) {
    const error = new Error('cloud inspection input must be a regular file');
    error.code = 'CLOUD_INSPECTION_INVALID_FILE';
    throw error;
  }
  if (before.size <= 0) {
    const error = new Error('cloud inspection input is empty');
    error.code = 'CLOUD_INSPECTION_EMPTY_FILE';
    throw error;
  }
  if (before.size > maxBytes) {
    const error = new Error('cloud inspection input exceeds upload limit');
    error.code = 'CLOUD_INSPECTION_FILE_TOO_LARGE';
    throw error;
  }

  const handle = await fs.promises.open(resolved, fs.constants.O_RDONLY);
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || opened.size !== before.size || opened.mtimeMs !== before.mtimeMs) {
      const error = new Error('cloud inspection input changed before upload');
      error.code = 'CLOUD_INSPECTION_FILE_CHANGED';
      throw error;
    }
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (bytes.length !== opened.size || after.size !== opened.size || after.mtimeMs !== opened.mtimeMs) {
      const error = new Error('cloud inspection input changed while reading');
      error.code = 'CLOUD_INSPECTION_FILE_CHANGED';
      throw error;
    }
    return {
      resolved,
      bytes,
      sha256: crypto.createHash('sha256').update(bytes).digest('hex'),
    };
  } finally {
    await handle.close().catch(() => {});
  }
}

class CloudEphemeralInspectionClient {
  constructor({
    endpoint = process.env.MALGUARD_CLOUD_SANDBOX_URL || DEFAULT_ENDPOINT,
    fetchImpl = globalThis.fetch,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    maxBytes = MAX_CLOUD_INSPECTION_BYTES,
  } = {}) {
    this.endpoint = String(endpoint || '').trim();
    this.fetchImpl = fetchImpl;
    this.timeoutMs = Math.max(5_000, Number(timeoutMs) || DEFAULT_TIMEOUT_MS);
    this.maxBytes = Math.max(1024, Number(maxBytes) || MAX_CLOUD_INSPECTION_BYTES);
  }

  available() {
    try {
      const url = new URL(this.endpoint);
      return typeof this.fetchImpl === 'function' && url.protocol === 'https:';
    } catch (_) {
      return false;
    }
  }

  async inspect(filePath) {
    if (!this.available()) {
      return { ok: false, code: 'CLOUD_INSPECTION_UNAVAILABLE', executionAttempted: false };
    }

    let stable;
    try {
      stable = await readStableFile(filePath, this.maxBytes);
    } catch (error) {
      return { ok: false, code: error.code || 'CLOUD_INSPECTION_READ_FAILED', executionAttempted: false };
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await this.fetchImpl(this.endpoint, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'accept': 'application/json',
          'user-agent': 'MalGuard-Desktop-Cloud-Inspection/1',
        },
        body: JSON.stringify({
          name: path.basename(stable.resolved).slice(0, 160),
          data: stable.bytes.toString('base64'),
        }),
        signal: controller.signal,
        redirect: 'error',
      });

      if (!response || response.ok !== true) {
        return {
          ok: false,
          code: 'CLOUD_INSPECTION_HTTP_FAILED',
          status: response && Number.isInteger(response.status) ? response.status : null,
          executionAttempted: false,
        };
      }

      const result = await response.json();
      const report = result && result.report;
      const isolation = result && result.isolation;
      const integrityOk = !!(result && result.ok === true && report
        && report.sha256 === stable.sha256
        && report.bytes === stable.bytes.length);
      const isolationOk = !!(isolation
        && isolation.ephemeral === true
        && isolation.networkPolicy === 'deny-all'
        && isolation.hostFallback === false
        && isolation.destroyAfterRun === true
        && isolation.execution === 'inspection-only');

      if (!integrityOk || !isolationOk) {
        return {
          ok: false,
          code: !integrityOk ? 'CLOUD_INSPECTION_INTEGRITY_FAILED' : 'CLOUD_INSPECTION_ISOLATION_EVIDENCE_FAILED',
          executionAttempted: false,
        };
      }

      return {
        ok: true,
        mode: 'cloud_ephemeral_inspection',
        provider: 'vercel-sandbox',
        executionAttempted: false,
        sampleSha256: stable.sha256,
        report: {
          bytes: report.bytes,
          sha256: report.sha256,
          type: report.type || 'unknown',
        },
        isolation: {
          ephemeral: true,
          networkPolicy: 'deny-all',
          hostFallback: false,
          destroyAfterRun: true,
          execution: 'inspection-only',
        },
        note: 'Cloud fallback inspects the uploaded file inside a disposable isolated environment. It does not execute Windows samples and cannot prove a file safe.',
      };
    } catch (error) {
      return {
        ok: false,
        code: error && error.name === 'AbortError' ? 'CLOUD_INSPECTION_TIMEOUT' : 'CLOUD_INSPECTION_REQUEST_FAILED',
        executionAttempted: false,
      };
    } finally {
      clearTimeout(timer);
    }
  }
}

module.exports = {
  CloudEphemeralInspectionClient,
  DEFAULT_ENDPOINT,
  DEFAULT_TIMEOUT_MS,
  MAX_CLOUD_INSPECTION_BYTES,
  readStableFile,
};
