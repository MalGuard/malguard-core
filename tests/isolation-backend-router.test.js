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
  const micro = new FakeBackend('microvm', { available: false });
  const portable = new FakeBackend('portable-vm', { available: true, containment: true, isolation: true });
  const windows = new FakeBackend('windows-sandbox', { available: false });
  const router = new IsolationBackendRouter({
    microVmBackend: micro,
    portableVmBackend: portable,
    windowsSandboxBackend: windows,
    prefer: 'microvm',
  });

  const before = await router.capabilities();
  assert.equal(before.selectedBackend, 'portable-vm', 'portable VM must be selected when preferred MicroVM is unavailable');
  assert.equal(before.alternatives.portableVm.requiresWindowsSandbox, false);
  assert.equal(before.alternatives.portableVm.requiresVtxAmdV, false);
  assert.equal(before.releaseGrade, false);

  const containment = await router.runContainmentSelfTest();
  assert.equal(containment.ok, true);
  assert.equal(containment.backend, 'portable-vm');
  const isolation = await router.runIsolationSelfTest();
  assert.equal(isolation.ok, true);
  assert.equal(isolation.backend, 'portable-vm');
  const ready = await router.capabilities();
  assert.equal(ready.selectedBackend, 'portable-vm');
  assert.equal(ready.releaseGrade, true);
  const result = await router.analyze('synthetic.cmd');
  assert.equal(result.ok, true);
  assert.equal(result.backend, 'portable-vm');

  const brokenPortable = new FakeBackend('portable-vm', { available: true, containment: true, isolation: false });
  const workingWindows = new FakeBackend('windows-sandbox', { available: true, containment: true, isolation: true });
  const fallbackRouter = new IsolationBackendRouter({
    microVmBackend: new FakeBackend('microvm', { available: false }),
    portableVmBackend: brokenPortable,
    windowsSandboxBackend: workingWindows,
    prefer: 'portable-vm',
  });
  assert.equal((await fallbackRouter.runContainmentSelfTest()).backend, 'portable-vm');
  const fallbackIsolation = await fallbackRouter.runIsolationSelfTest();
  assert.equal(fallbackIsolation.ok, true);
  assert.equal(fallbackIsolation.backend, 'windows-sandbox', 'router must fail over instead of pretending a broken VM is certified');

  const none = new IsolationBackendRouter({
    microVmBackend: new FakeBackend('microvm', { available: false }),
    portableVmBackend: new FakeBackend('portable-vm', { available: false }),
    windowsSandboxBackend: new FakeBackend('windows-sandbox', { available: false }),
  });
  const denied = await none.analyze('synthetic.cmd');
  assert.equal(denied.ok, false);
  assert.equal(denied.verdict, 'inconclusive');
  assert.equal(denied.code, 'NO_RELEASE_GRADE_ISOLATION_BACKEND');

  console.log('✓ Isolation backend router: portable VM preference, Windows fallback and fail-closed no-backend policy PASS');
})().catch(error => {
  console.error(error.stack || error);
  process.exit(1);
});
