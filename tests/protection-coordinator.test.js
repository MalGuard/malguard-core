'use strict';

const assert = require('assert');
const { ProtectionCoordinator } = require('../desktop-guard/windows-agent/protection-coordinator.js');

function fakeAgent({ healthy = true } = {}) {
  const calls = [];
  let active = false;
  return {
    calls,
    async startWatching() { calls.push('watch:start'); active = true; return { ok:healthy, active:true, health:{ state:healthy ? 'healthy' : 'degraded' } }; },
    async stopWatching() { calls.push('watch:stop'); active = false; return { ok:true, active:false, health:{ state:'stopped' } }; },
    getHealth() { return { state:active && healthy ? 'healthy' : (active ? 'degraded' : 'stopped'), watcher:{ active } }; },
  };
}

function fakeGate({ initiallyProtected = false } = {}) {
  const calls = [];
  let protectedNow = initiallyProtected;
  return {
    calls,
    async protectAll() { calls.push('gate:protect'); protectedNow = true; return { ok:true, results:[{ protected:true }] }; },
    async restoreAll() { calls.push('gate:restore'); protectedNow = false; return { ok:true, results:[{ protected:false }] }; },
    async status() { calls.push('gate:status'); return { ok:true, supported:true, protected:protectedNow }; },
    setProtected(value) { protectedNow = value === true; },
  };
}

(async () => {
  // Complete protection must establish the folder gate before the watcher starts.
  const order = [];
  const agent = fakeAgent();
  const gate = fakeGate();
  const originalProtect = gate.protectAll.bind(gate);
  gate.protectAll = async () => { order.push('protect'); return originalProtect(); };
  const originalStatus = gate.status.bind(gate);
  gate.status = async () => { order.push('verify'); return originalStatus(); };
  const originalStart = agent.startWatching.bind(agent);
  agent.startWatching = async () => { order.push('watch'); return originalStart(); };
  const coordinator = new ProtectionCoordinator({ agent, accessGate:gate, serviceMode:true, platform:'win32', monitorIntervalMs:60000 });
  const started = await coordinator.start();
  assert.equal(started.ok, true);
  assert.equal(started.completeProtection, true);
  assert.equal(started.accessGateProtected, true);
  assert.equal(started.watcherHealthy, true);
  assert.deepEqual(order.slice(0, 3), ['protect', 'verify', 'watch']);

  // If protection is disturbed while active, the coordinator repairs it before
  // it can continue claiming complete protection.
  gate.setProtected(false);
  const repaired = await coordinator._checkGate();
  assert.equal(repaired.completeProtection, true);
  assert(gate.calls.filter(x => x === 'gate:protect').length >= 2);

  const stopped = await coordinator.stop();
  assert.equal(stopped.ok, true);
  assert.equal(stopped.active, false);
  assert.equal(stopped.accessGateProtected, false);
  assert(agent.calls.includes('watch:stop'));
  assert(gate.calls.includes('gate:restore'));

  // Direct desktop mode may not advertise race-free protection, because the
  // protected-folder policy is designed to work with the Windows service path.
  const directAgent = fakeAgent();
  const directGate = fakeGate();
  const direct = new ProtectionCoordinator({ agent:directAgent, accessGate:directGate, serviceMode:false, platform:'win32' });
  const directResult = await direct.start();
  assert.equal(directResult.ok, false);
  assert.equal(directResult.reason, 'REALTIME_PROTECTION_SERVICE_REQUIRED');
  assert.equal(directGate.calls.length, 0);
  assert.equal(directAgent.calls.length, 0);

  // If watcher startup fails after folder protection was established, keep the
  // folder protected instead of silently reopening the write window.
  const weakAgent = fakeAgent({ healthy:false });
  const safeGate = fakeGate();
  const guarded = new ProtectionCoordinator({ agent:weakAgent, accessGate:safeGate, serviceMode:true, platform:'win32' });
  const guardedResult = await guarded.start();
  assert.equal(guardedResult.ok, false);
  assert.equal(guardedResult.completeProtection, false);
  assert.equal(guardedResult.accessGateProtected, true);
  assert.equal(guardedResult.state, 'fail_closed');
  assert.equal(safeGate.calls.includes('gate:restore'), false);
  const guardedStop = await guarded.stop();
  assert.equal(guardedStop.ok, true);
  assert.equal(guardedStop.accessGateProtected, false);

  // Unsupported hosts never pretend that the guarantee exists.
  const other = new ProtectionCoordinator({ agent:fakeAgent(), accessGate:fakeGate(), serviceMode:true, platform:'linux' });
  const otherResult = await other.start();
  assert.equal(otherResult.ok, false);
  assert.equal(otherResult.reason, 'REALTIME_PROTECTION_WINDOWS_REQUIRED');

  console.log('✓ Real-time protection coordinator: access gate before watcher, repair monitoring, service-only activation and fail-closed startup PASS');
})().catch(error => { console.error(error.stack || error); process.exit(1); });
