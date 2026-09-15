'use strict';

(function (root) {
  function clean(value) {
    return typeof value === 'string' ? value.trim() : '';
  }

  function createIncidentReport(input) {
    if (!input || typeof input !== 'object') throw new TypeError('incident input required');
    const timestamp = Number.isFinite(input.timestamp) && input.timestamp > 0 ? input.timestamp : Date.now();
    return Object.freeze({
      schemaVersion: '1.0.0',
      incidentId: clean(input.incidentId) || `mg-${timestamp}-${Math.random().toString(36).slice(2, 10)}`,
      modName: clean(input.modName) || 'Unknown mod',
      responsibleFile: clean(input.responsibleFile) || 'Unknown file',
      verdict: clean(input.verdict) || 'INCONCLUSIVE',
      reason: clean(input.reason) || 'unspecified',
      action: clean(input.action) || 'hold',
      timestamp,
      source: clean(input.source) || 'desktop-guard',
    });
  }

  const api = Object.freeze({ version: '0.1.0', createIncidentReport });
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.MalGuardIncidentReport = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
