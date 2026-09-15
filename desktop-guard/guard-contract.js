'use strict';

(function (root) {
  const VERSION = '0.2.0';
  const EVENT_TYPES = Object.freeze({
    FILE_DISCOVERED: 'file_discovered',
    FILE_CREATED: 'file_created',
    FILE_CHANGED: 'file_changed',
    FILE_MOVED: 'file_moved',
    FILE_REMOVED: 'file_removed',
  });
  const VERDICTS = Object.freeze({
    SAFE: 'SAFE',
    SUSPICIOUS: 'SUSPICIOUS',
    MALICIOUS: 'MALICIOUS',
    INCONCLUSIVE: 'INCONCLUSIVE',
  });
  const ACTIONS = Object.freeze({
    RELEASE: 'release',
    QUARANTINE: 'quarantine',
    BLOCK_AND_QUARANTINE: 'block_and_quarantine',
    HOLD: 'hold',
  });

  function isNonEmptyString(value) {
    return typeof value === 'string' && value.trim().length > 0;
  }

  function validateGuardEvent(event) {
    if (!event || typeof event !== 'object') return { ok: false, error: 'EVENT_REQUIRED' };
    if (!Object.values(EVENT_TYPES).includes(event.type)) return { ok: false, error: 'INVALID_EVENT_TYPE' };
    if (!isNonEmptyString(event.path)) return { ok: false, error: 'INVALID_PATH' };
    if (!Number.isFinite(event.timestamp) || event.timestamp <= 0) return { ok: false, error: 'INVALID_TIMESTAMP' };
    if (event.size != null && (!Number.isFinite(event.size) || event.size < 0)) return { ok: false, error: 'INVALID_SIZE' };
    return { ok: true };
  }

  function validateScanVerdict(result) {
    if (!result || typeof result !== 'object') return { ok: false, error: 'RESULT_REQUIRED' };
    if (!Object.values(VERDICTS).includes(result.verdict)) return { ok: false, error: 'INVALID_VERDICT' };
    if (result.reasons != null && !Array.isArray(result.reasons)) return { ok: false, error: 'INVALID_REASONS' };
    return { ok: true };
  }

  const api = Object.freeze({ version: VERSION, EVENT_TYPES, VERDICTS, ACTIONS, validateGuardEvent, validateScanVerdict });
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.MalGuardDesktopGuardContract = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
