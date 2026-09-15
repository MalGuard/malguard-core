'use strict';

const TELEMETRY_SCHEMA_VERSION = '1.1.0';
const MAX_RESULT_BYTES = 512 * 1024;
const MAX_PROCESS_ROWS = 512;
const MAX_FILE_ROWS = 512;
const MAX_STRING = 2048;

function isIsoDate(value) {
  if (typeof value !== 'string' || value.length > 64) return false;
  const t = Date.parse(value);
  return Number.isFinite(t);
}

function safeString(value, max = MAX_STRING) {
  if (typeof value !== 'string') return null;
  return value.length <= max ? value : null;
}

function validateProcessRow(row) {
  if (!row || typeof row !== 'object' || Array.isArray(row)) return null;
  const id = Number(row.Id ?? row.id);
  const name = safeString(row.ProcessName ?? row.processName, 256);
  const procPath = row.Path == null && row.path == null ? null : safeString(row.Path ?? row.path);
  if (!Number.isInteger(id) || id < 0 || !name) return null;
  return { id, processName: name, path: procPath };
}

function validateFileRow(row) {
  if (!row || typeof row !== 'object' || Array.isArray(row)) return null;
  const fullName = safeString(row.FullName ?? row.fullName);
  const length = Number(row.Length ?? row.length);
  const written = row.LastWriteTimeUtc ?? row.lastWriteTimeUtc;
  if (!fullName || !Number.isFinite(length) || length < 0 || !isIsoDate(String(written))) return null;
  return { fullName, length, lastWriteTimeUtc: new Date(written).toISOString() };
}

function validateExecution(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const attempted = value.attempted === true;
  const started = value.started === true;
  const timedOut = value.timedOut === true;
  const exitCode = value.exitCode == null ? null : Number(value.exitCode);
  const error = value.error == null ? null : safeString(value.error);
  const cpuBudgetExceeded = value.cpuBudgetExceeded === true;
  const outputQuotaExceeded = value.outputQuotaExceeded === true;
  if (exitCode != null && !Number.isInteger(exitCode)) return null;
  if (value.error != null && error == null) return null;
  return { attempted, started, timedOut, exitCode, error, cpuBudgetExceeded, outputQuotaExceeded };
}

function validateTelemetry(raw, expectedSessionId) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { ok: false, code: 'SANDBOX_TELEMETRY_INVALID_OBJECT' };
  }
  if (raw.schemaVersion !== TELEMETRY_SCHEMA_VERSION) {
    return { ok: false, code: 'SANDBOX_TELEMETRY_SCHEMA_MISMATCH' };
  }
  if (typeof raw.sessionId !== 'string' || raw.sessionId !== expectedSessionId) {
    return { ok: false, code: 'SANDBOX_TELEMETRY_SESSION_MISMATCH' };
  }
  if (!isIsoDate(raw.startedAt) || !isIsoDate(raw.finishedAt)) {
    return { ok: false, code: 'SANDBOX_TELEMETRY_TIMESTAMP_INVALID' };
  }
  const started = Date.parse(raw.startedAt);
  const finished = Date.parse(raw.finishedAt);
  if (finished < started || finished - started > 10 * 60 * 1000) {
    return { ok: false, code: 'SANDBOX_TELEMETRY_TIME_RANGE_INVALID' };
  }
  const execution = validateExecution(raw.execution);
  if (!execution) return { ok: false, code: 'SANDBOX_TELEMETRY_EXECUTION_INVALID' };

  if (!Array.isArray(raw.baselineProcesses) || raw.baselineProcesses.length > MAX_PROCESS_ROWS) {
    return { ok: false, code: 'SANDBOX_TELEMETRY_BASELINE_PROCESSES_INVALID' };
  }
  if (!Array.isArray(raw.finalProcesses) || raw.finalProcesses.length > MAX_PROCESS_ROWS) {
    return { ok: false, code: 'SANDBOX_TELEMETRY_FINAL_PROCESSES_INVALID' };
  }
  if (!Array.isArray(raw.recentFiles) || raw.recentFiles.length > MAX_FILE_ROWS) {
    return { ok: false, code: 'SANDBOX_TELEMETRY_FILES_INVALID' };
  }

  const baselineProcesses = raw.baselineProcesses.map(validateProcessRow);
  const finalProcesses = raw.finalProcesses.map(validateProcessRow);
  const recentFiles = raw.recentFiles.map(validateFileRow);
  if (baselineProcesses.some(v => !v) || finalProcesses.some(v => !v) || recentFiles.some(v => !v)) {
    return { ok: false, code: 'SANDBOX_TELEMETRY_ROW_INVALID' };
  }

  const networkPolicy = safeString(raw.networkPolicy, 128);
  if (networkPolicy !== 'disabled-by-wsb') {
    return { ok: false, code: 'SANDBOX_TELEMETRY_NETWORK_POLICY_INVALID' };
  }

  return {
    ok: true,
    telemetry: {
      schemaVersion: TELEMETRY_SCHEMA_VERSION,
      sessionId: raw.sessionId,
      startedAt: new Date(raw.startedAt).toISOString(),
      finishedAt: new Date(raw.finishedAt).toISOString(),
      networkPolicy,
      execution,
      baselineProcesses,
      finalProcesses,
      recentFiles,
    },
  };
}

function evaluateTelemetry(telemetry) {
  if (!telemetry || typeof telemetry !== 'object') {
    return { verdict: 'inconclusive', riskScore: 0, signals: ['telemetry_missing'] };
  }
  const signals = [];
  let riskScore = 0;

  if (telemetry.execution && telemetry.execution.timedOut) {
    signals.push('execution_timeout');
    riskScore += 25;
  }
  if (telemetry.execution && telemetry.execution.cpuBudgetExceeded) {
    signals.push('cpu_budget_exceeded');
    riskScore += 20;
  }
  if (telemetry.execution && telemetry.execution.outputQuotaExceeded) {
    signals.push('output_quota_exceeded');
    riskScore += 25;
  }
  if (telemetry.execution && telemetry.execution.error) {
    signals.push('execution_error');
    riskScore += 5;
  }

  const baselineIds = new Set((telemetry.baselineProcesses || []).map(p => p.id));
  const spawned = (telemetry.finalProcesses || []).filter(p => !baselineIds.has(p.id));
  if (spawned.length >= 8) {
    signals.push('high_process_fanout');
    riskScore += 20;
  } else if (spawned.length >= 3) {
    signals.push('process_fanout');
    riskScore += 10;
  }

  const files = telemetry.recentFiles || [];
  if (files.length >= 100) {
    signals.push('high_file_write_volume');
    riskScore += 25;
  } else if (files.length >= 20) {
    signals.push('file_write_volume');
    riskScore += 10;
  }

  // Behavioral telemetry is deliberately conservative. It can raise suspicion,
  // but absence of observed signals never proves a sample safe.
  const verdict = riskScore >= 25 ? 'suspicious' : 'inconclusive';
  return { verdict, riskScore: Math.min(100, riskScore), signals };
}

module.exports = {
  TELEMETRY_SCHEMA_VERSION,
  MAX_RESULT_BYTES,
  MAX_PROCESS_ROWS,
  MAX_FILE_ROWS,
  validateTelemetry,
  evaluateTelemetry,
};
