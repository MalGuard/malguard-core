'use strict';

const crypto = require('crypto');

const MAX_FIXTURE_BYTES = 64 * 1024;
const ALLOWED_FIXTURE = Buffer.from('MALGUARD_SAFE_SANDBOX_FIXTURE_V1\n', 'utf8');

function sha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function validateSafeFixture(data) {
  if (!Buffer.isBuffer(data)) throw new TypeError('fixture must be a Buffer');
  if (data.length === 0 || data.length > MAX_FIXTURE_BYTES) return { ok: false, reason: 'size' };
  if (!data.equals(ALLOWED_FIXTURE)) return { ok: false, reason: 'phase1-safe-fixtures-only' };
  return { ok: true, sha256: sha256(data), bytes: data.length };
}

function createIsolationJob(data) {
  const fixture = validateSafeFixture(data);
  if (!fixture.ok) return { accepted: false, ...fixture };
  return {
    accepted: true,
    jobId: crypto.randomUUID(),
    fixture,
    isolation: {
      ephemeral: true,
      networkPolicy: 'deny-all',
      publicPorts: [],
      secrets: [],
      timeoutMs: 30_000,
      hostFallback: false,
      destroyAfterRun: true
    }
  };
}

module.exports = { ALLOWED_FIXTURE, MAX_FIXTURE_BYTES, validateSafeFixture, createIsolationJob };
