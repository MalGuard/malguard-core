'use strict';

const { SafeSelfHeal } = require('./self-heal.js');

let report;
try {
  report = new SafeSelfHeal().repairSync();
} catch (error) {
  report = Object.freeze({
    selfHealVersion: '1.0.0',
    ok: false,
    degraded: true,
    repaired: false,
    actions: [],
    blockers: [{ id: 'startup-self-heal', code: String((error && (error.code || error.message)) || 'SELF_HEAL_FAILED') }],
    note: 'Startup continues in degraded mode so independent scan capabilities remain available.',
    timestamp: new Date().toISOString(),
  });
}

Object.defineProperty(globalThis, '__MALGUARD_SELF_HEAL__', {
  value: report,
  enumerable: false,
  configurable: false,
  writable: false,
});

if (!report.ok) {
  process.stderr.write(`MalGuard startup self-heal degraded: ${report.blockers.map(item => item.code).join(', ')}\n`);
}
