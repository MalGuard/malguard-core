'use strict';

const { LocalErrorReporter, safeText } = require('../diagnostics/error-reporter.js');

const DEFAULT_PORT = 18777;
const DEFAULT_TIMEOUT_MS = 3000;
const MAX_RECENT_LOGS = 20;

function normalizePort(value) {
  const port = Number(value);
  return Number.isInteger(port) && port > 0 && port <= 65535 ? port : DEFAULT_PORT;
}

function localStatusUrl(port) {
  return 'http://127.0.0.1:' + normalizePort(port) + '/api/status';
}

function safeOptionalText(value, max) {
  const text = safeText(value == null ? '' : value, max);
  return text || null;
}

function safeArray(values, maxItems = 20, maxText = 256) {
  if (!Array.isArray(values)) return [];
  return values.slice(0, maxItems).map(value => safeText(value, maxText)).filter(Boolean);
}

async function fetchLocalStatus({ fetchImpl, port, timeoutMs }) {
  if (typeof fetchImpl !== 'function') {
    const error = new Error('Fetch implementation unavailable.');
    error.code = 'MALGUARD_LOCAL_FETCH_UNAVAILABLE';
    throw error;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    let response;
    try {
      response = await fetchImpl(localStatusUrl(port), {
        method: 'GET',
        headers: { accept: 'application/json' },
        signal: controller.signal,
      });
    } catch (error) {
      const wrapped = new Error('MalGuard local service is unavailable.');
      wrapped.code = error && error.name === 'AbortError'
        ? 'MALGUARD_LOCAL_TIMEOUT'
        : 'MALGUARD_LOCAL_UNAVAILABLE';
      throw wrapped;
    }

    if (!response || response.ok !== true) {
      const error = new Error('MalGuard local service returned an unsuccessful status.');
      error.code = 'MALGUARD_LOCAL_HTTP_ERROR';
      throw error;
    }

    let payload;
    try {
      payload = await response.json();
    } catch (_) {
      const error = new Error('MalGuard local service returned invalid JSON.');
      error.code = 'MALGUARD_LOCAL_INVALID_JSON';
      throw error;
    }

    if (!payload || payload.ok !== true) {
      const error = new Error('MalGuard local service status is not ready.');
      error.code = 'MALGUARD_LOCAL_NOT_READY';
      throw error;
    }

    return payload;
  } finally {
    clearTimeout(timer);
  }
}

function projectStatus(payload, generatedAt) {
  const protection = payload.realtimeProtection && typeof payload.realtimeProtection === 'object'
    ? payload.realtimeProtection
    : {};
  const guardHealth = payload.guardHealth && typeof payload.guardHealth === 'object'
    ? payload.guardHealth
    : {};

  return {
    ok: true,
    generatedAt,
    product: safeText(payload.product || 'MalGuard Desktop', 128),
    version: safeText(payload.version || 'unknown', 64),
    build: safeOptionalText(payload.build, 64),
    guardConfigured: payload.guardConfigured === true,
    watching: payload.watching === true,
    realtimeProtection: {
      active: protection.active === true,
      completeProtection: protection.completeProtection === true,
      accessGateProtected: protection.accessGateProtected === true,
      watcherHealthy: protection.watcherHealthy === true,
      runtimeProcessHealthy: protection.runtimeProcessHealthy === true,
      state: safeText(protection.state || 'unknown', 64),
      reason: safeOptionalText(protection.reason, 256),
    },
    guardHealth: {
      state: safeText(guardHealth.state || 'unknown', 64),
    },
    sandboxMode: safeOptionalText(payload.sandboxMode, 128),
  };
}

function projectSandboxHealth(payload, generatedAt) {
  const certification = payload.sandboxCertification && typeof payload.sandboxCertification === 'object'
    ? payload.sandboxCertification
    : {};
  const automatic = certification.automatic && typeof certification.automatic === 'object'
    ? certification.automatic
    : {};

  return {
    ok: true,
    generatedAt,
    sandboxReady: certification.ok === true,
    sandboxMode: safeText(payload.sandboxMode || 'unknown', 128),
    certification: {
      state: safeText(certification.state || 'unknown', 64),
      ok: certification.ok === true,
      sandboxVersion: safeOptionalText(certification.sandboxVersion, 64),
      certifiedAt: safeOptionalText(certification.certifiedAt, 64),
      isolationBackendReady: certification.isolationBackendReady === true,
      windowsSandboxReady: certification.windowsSandboxReady === true,
      executionCertified: certification.executionCertified === true,
      selectedBackend: safeOptionalText(certification.selectedBackend, 128),
      blockers: safeArray(certification.blockers),
      automatic: {
        enabled: automatic.enabled === true,
        scheduled: automatic.scheduled === true,
        startedAt: safeOptionalText(automatic.startedAt, 64),
        completedAt: safeOptionalText(automatic.completedAt, 64),
      },
    },
  };
}

function projectReport(report) {
  const context = report && report.context && typeof report.context === 'object'
    ? report.context
    : {};
  const runtime = report && report.runtime && typeof report.runtime === 'object'
    ? report.runtime
    : {};

  return {
    time: safeOptionalText(report && report.time, 64),
    code: safeText(report && report.code ? report.code : 'UNKNOWN', 128),
    name: safeText(report && report.name ? report.name : 'Error', 128),
    message: safeText(report && report.message ? report.message : '', 1024),
    context: {
      area: safeText(context.area || 'runtime', 128),
      method: safeText(context.method || '', 16),
      route: safeText(context.route || '', 256),
    },
    runtime: {
      node: safeText(runtime.node || '', 64),
      platform: safeText(runtime.platform || '', 32),
      arch: safeText(runtime.arch || '', 32),
    },
  };
}

function safeFailure(code, message, generatedAt) {
  return {
    ok: false,
    generatedAt,
    code: safeText(code || 'MCP_READ_FAILED', 128),
    message: safeText(message || 'The requested MalGuard read-only status is unavailable.', 256),
  };
}

function createReadOnlyTools(options = {}) {
  const fetchImpl = options.fetchImpl || globalThis.fetch;
  const errorReporter = options.errorReporter || new LocalErrorReporter();
  const port = normalizePort(options.port == null ? process.env.MALGUARD_PORT : options.port);
  const timeoutMs = Number.isFinite(options.timeoutMs) && options.timeoutMs > 0
    ? Math.min(10000, Math.floor(options.timeoutMs))
    : DEFAULT_TIMEOUT_MS;
  const now = typeof options.now === 'function' ? options.now : () => new Date().toISOString();

  return {
    async getMalguardStatus() {
      const generatedAt = now();
      try {
        const payload = await fetchLocalStatus({ fetchImpl, port, timeoutMs });
        return projectStatus(payload, generatedAt);
      } catch (error) {
        return safeFailure(
          error && error.code,
          error && error.code === 'MALGUARD_LOCAL_TIMEOUT'
            ? 'MalGuard local service did not answer before the read-only timeout.'
            : 'MalGuard local service is unavailable or not ready.',
          generatedAt,
        );
      }
    },

    async getSandboxHealth() {
      const generatedAt = now();
      try {
        const payload = await fetchLocalStatus({ fetchImpl, port, timeoutMs });
        return projectSandboxHealth(payload, generatedAt);
      } catch (error) {
        return safeFailure(
          error && error.code,
          error && error.code === 'MALGUARD_LOCAL_TIMEOUT'
            ? 'MalGuard local service did not answer before the read-only timeout.'
            : 'MalGuard local service is unavailable or not ready.',
          generatedAt,
        );
      }
    },

    async getRecentLogs() {
      const generatedAt = now();
      try {
        const reports = await errorReporter.list(MAX_RECENT_LOGS);
        const safeReports = Array.isArray(reports)
          ? reports.slice(0, MAX_RECENT_LOGS).map(projectReport)
          : [];
        return {
          ok: true,
          generatedAt,
          count: safeReports.length,
          reports: safeReports,
          privacy: {
            bounded: true,
            maxReports: MAX_RECENT_LOGS,
            pathsRedacted: true,
            longSecretsRedacted: true,
            stacksExcluded: true,
          },
        };
      } catch (_) {
        return safeFailure(
          'MALGUARD_DIAGNOSTICS_UNAVAILABLE',
          'MalGuard local diagnostics are unavailable.',
          generatedAt,
        );
      }
    },
  };
}

module.exports = {
  DEFAULT_PORT,
  DEFAULT_TIMEOUT_MS,
  MAX_RECENT_LOGS,
  createReadOnlyTools,
  fetchLocalStatus,
  projectStatus,
  projectSandboxHealth,
  projectReport,
};
