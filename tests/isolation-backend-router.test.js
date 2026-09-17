'use strict';

const assert = require('assert');
const { IsolationBackendRouter } = require('../desktop-app/sandbox/isolation-backend-router.js');

class FakeBackend {
  constructor(name, { available = true, containment = true, isolation = true } = {}) {
    this.name = name;
    this.available = available;
    this.containmentPass = containment;
    this.isolationPass = isolation;
    this.containmentAccepted = false;
    this.isolationAccepted = false;
    this.calls = [];
  }
  async capabilities() {
    return {
      backend: this.name,
      available: this.available,
      releaseGrade: this.available && this.containmentAccepted && this.isolationAccepted,
      blockers: this.available ? [] : [`${this.name}_unavailable`],
      requiresWindowsSandbox: this.name === 'windows-sandbox',
      requiresVtxAmdV: this.name === 'portable-vm' ? false : null,
    };
  }
  async runContainmentSelfTest() {
    this.calls.push('containment');
    this.containmentAccepted = this.available && this.containmentPass;
    return this.containmentAccepted ? { ok: true } : { ok: false, code: `${this.name}_containment_failed` };
  }
  async runIsolationSelfTest() {
    this.calls.push('isolation');
    this.isolationAccepted = this.containmentAccepted && this.isolationPass;
    return this.isolationAccepted ? { ok: true } : { ok: false, code: `${this.name}_isolation_failed` };
  }
  async analyze(samplePath) {
    this.calls.push('analyze');
    const caps = await this.capabilities();
    if (!caps.releaseGrade) return { ok: false, verdict: 'inconclusive', code: `${this.name}_not_certified` };
    return {
      ok: true,
      verdict: 'suspicious',
      backend: this.name,
      samplePath,
      sandboxLaunched: true,
      sampleExecutionStarted: true,
      telemetry: { execution: { attempted: true, started: true } },
    };
  }
}

(async () => {
  // Normal Windows laptop: certified Windows Sandbox is the first choice.
  const windows = new FakeBackend('windows-sandbox', { available: true, containment: true, isolation: true });
  const micro = new FakeBackend('microvm', { available: true, containment: true, isolation: true });
  const portable = new FakeBackend('portable-vm', { available: true, containment: true, isolation: true });
  const windowsFirst = new IsolationBackendRouter({
    microVmBackend: micro,
    portableVmBackend: portable,
    windowsSandboxBackend: windows,
  });
  const initial = await windowsFirst.capabilities();
  assert.equal(initial.preferredBackend, 'windows-sandbox');
  assert.deepEqual(initial.fallbackOrder, ['windows-sandbox', 'microvm', 'portable-vm']);
  assert.equal(initial.requiresWindowsSandbox, false, 'Windows Sandbox must be optional, not a hard dependency');
  assert.equal(initial.windowsSandboxOptional, true);
  assert.equal((await windowsFirst.runContainmentSelfTest()).backend, 'windows-sandbox');
  assert.equal((await windowsFirst.runIsolationSelfTest()).backend, 'windows-sandbox');
  const winResult = await windowsFirst.analyze('synthetic.cmd');
  assert.equal(winResult.ok, true);
  assert.equal(winResult.backend, 'windows-sandbox');
  assert.equal(micro.calls.length, 0, 'MalGuard VM should not be touched when Windows Sandbox is certified');

  // Windows Sandbox unavailable: fail over to the MalGuard-owned isolation stack.
  const noWindows = new IsolationBackendRouter({
    windowsSandboxBackend: new FakeBackend('windows-sandbox', { available: false }),
    microVmBackend: new FakeBackend('microvm', { available: false }),
    portableVmBackend: new FakeBackend('portable-vm', { available: true, containment: true, isolation: true }),
  });
  const beforeFallback = await noWindows.capabilities();
  assert.equal(beforeFallback.selectedBackend, 'portable-vm');
  assert.equal(beforeFallback.alternatives.portableVm.requiresWindowsSandbox, false);
  assert.equal(beforeFallback.alternatives.portableVm.requiresVtxAmdV, false);
  assert.equal((await noWindows.runContainmentSelfTest()).backend, 'portable-vm');
  assert.equal((await noWindows.runIsolationSelfTest()).backend, 'portable-vm');
  const fallbackResult = await noWindows.analyze('synthetic.cmd');
  assert.equal(fallbackResult.ok, true);
  assert.equal(fallbackResult.backend, 'portable-vm');

  // Windows Sandbox exists but cannot pass isolation: never pretend success; use a certified fallback.
  const brokenWindows = new FakeBackend('windows-sandbox', { available: true, containment: true, isolation: false });
  const workingMicro = new FakeBackend('microvm', { available: true, containment: true, isolation: true });
  const safeFallback = new IsolationBackendRouter({
    windowsSandboxBackend: brokenWindows,
    microVmBackend: workingMicro,
    portableVmBackend: new FakeBackend('portable-vm', { available: true }),
  });
  assert.equal((await safeFallback.runContainmentSelfTest()).backend, 'windows-sandbox');
  const fallbackIsolation = await safeFallback.runIsolationSelfTest();
  assert.equal(fallbackIsolation.ok, true);
  assert.equal(fallbackIsolation.backend, 'microvm');

  // No certified backend means no host execution, ever.
  const none = new IsolationBackendRouter({
    windowsSandboxBackend: new FakeBackend('windows-sandbox', { available: false }),
    microVmBackend: new FakeBackend('microvm', { available: false }),
    portableVmBackend: new FakeBackend('portable-vm', { available: false }),
  });
  const denied = await none.analyze('synthetic.cmd');
  assert.equal(denied.ok, false);
  assert.equal(denied.verdict, 'inconclusive');
  assert.equal(denied.code, 'NO_RELEASE_GRADE_ISOLATION_BACKEND');

  console.log('✓ Isolation backend router: Windows Sandbox first, MalGuard VM fallback, and fail-closed no-backend policy PASS');
})().catch(error => {
  console.error(error.stack || error);
  process.exit(1);
});
