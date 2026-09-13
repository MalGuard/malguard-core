'use strict';

(function (root) {
  const contract = typeof require === 'function'
    ? require('./guard-contract.js')
    : root.MalGuardDesktopGuardContract;

  function decideContainment(scanResult) {
    const valid = contract.validateScanVerdict(scanResult);
    if (!valid.ok) return { action: contract.ACTIONS.HOLD, reason: valid.error, failClosed: true };

    switch (scanResult.verdict) {
      case contract.VERDICTS.SAFE:
        return { action: contract.ACTIONS.RELEASE, reason: 'verified_safe', failClosed: false };
      case contract.VERDICTS.SUSPICIOUS:
        return { action: contract.ACTIONS.QUARANTINE, reason: 'suspicious_content', failClosed: true };
      case contract.VERDICTS.MALICIOUS:
        return { action: contract.ACTIONS.BLOCK_AND_QUARANTINE, reason: 'malicious_content', failClosed: true };
      case contract.VERDICTS.INCONCLUSIVE:
      default:
        return { action: contract.ACTIONS.HOLD, reason: 'inconclusive', failClosed: true };
    }
  }

  const api = Object.freeze({ version: '0.2.0', decideContainment });
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.MalGuardContainmentPolicy = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
