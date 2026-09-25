'use strict';

const path = require('path');
const { readStableFile, MAX_CLOUD_INSPECTION_BYTES } = require('../sandbox/cloud-ephemeral-inspection.js');

const DEFAULT_GTA_SIMULATION_ENDPOINT = 'https://malguard-core-sandbox.vercel.app/api/cloud-gta-simulation';
const DEFAULT_TIMEOUT_MS = 45_000;
const ALLOWED_PLUGIN_EXTENSIONS = new Set(['.asi', '.dll']);

class CloudGtaSimulationClient {
  constructor({
    endpoint = process.env.MALGUARD_CLOUD_GTA_SIMULATION_URL || DEFAULT_GTA_SIMULATION_ENDPOINT,
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

  supports(filePath) {
    return ALLOWED_PLUGIN_EXTENSIONS.has(path.extname(String(filePath || '')).toLowerCase());
  }

  async simulate(filePath) {
    if (!this.available()) {
      return { ok: false, code: 'GTA_CLOUD_SIMULATION_UNAVAILABLE', sampleExecutionAttempted: false };
    }
    if (!this.supports(filePath)) {
      return { ok: false, code: 'GTA_CLOUD_SIMULATION_UNSUPPORTED_EXTENSION', sampleExecutionAttempted: false };
    }

    let stable;
    try {
      stable = await readStableFile(filePath, this.maxBytes);
    } catch (error) {
      return { ok: false, code: error.code || 'GTA_CLOUD_SIMULATION_READ_FAILED', sampleExecutionAttempted: false };
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await this.fetchImpl(this.endpoint, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'accept': 'application/json',
          'user-agent': 'MalGuard-Desktop-GTA-Simulation/1',
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
          code: 'GTA_CLOUD_SIMULATION_HTTP_FAILED',
          status: response && Number.isInteger(response.status) ? response.status : null,
          sampleExecutionAttempted: false,
        };
      }

      const result = await response.json();
      const report = result && result.report;
      const isolation = result && result.isolation;
      const integrityOk = !!(result && result.ok === true && result.mode === 'cloud_gta_simulation'
        && report && report.sha256 === stable.sha256 && report.bytes === stable.bytes.length);
      const safetyOk = !!(report
        && report.treeReady === true
        && report.sampleExecutionAttempted === false
        && report.sampleExecutionStarted === false
        && report.realGameFilesMounted === false
        && report.realUserFilesMounted === false
        && report.networkPolicy === 'deny-all');
      const isolationOk = !!(isolation
        && isolation.ephemeral === true
        && isolation.networkPolicy === 'deny-all'
        && isolation.hostFallback === false
        && isolation.destroyAfterRun === true
        && isolation.syntheticGameEnvironment === true);

      if (!integrityOk || !safetyOk || !isolationOk) {
        return {
          ok: false,
          code: !integrityOk
            ? 'GTA_CLOUD_SIMULATION_INTEGRITY_FAILED'
            : !safetyOk
              ? 'GTA_CLOUD_SIMULATION_SAFETY_EVIDENCE_FAILED'
              : 'GTA_CLOUD_SIMULATION_ISOLATION_EVIDENCE_FAILED',
          sampleExecutionAttempted: false,
        };
      }

      return {
        ok: true,
        mode: 'cloud_gta_simulation',
        provider: 'vercel-sandbox',
        sampleSha256: stable.sha256,
        sampleExecutionAttempted: false,
        sampleExecutionStarted: false,
        report,
        isolation,
        note: 'A synthetic GTA filesystem was created inside a disposable isolated environment. The plugin was staged but not executed.',
      };
    } catch (error) {
      return {
        ok: false,
        code: error && error.name === 'AbortError' ? 'GTA_CLOUD_SIMULATION_TIMEOUT' : 'GTA_CLOUD_SIMULATION_REQUEST_FAILED',
        sampleExecutionAttempted: false,
      };
    } finally {
      clearTimeout(timer);
    }
  }
}

module.exports = {
  CloudGtaSimulationClient,
  DEFAULT_GTA_SIMULATION_ENDPOINT,
  DEFAULT_TIMEOUT_MS,
  ALLOWED_PLUGIN_EXTENSIONS,
};
