'use strict';

const assert = require('assert');
const { SandboxController } = require('../desktop-app/sandbox/sandbox-controller.js');
const { IsolationBackendRouter } = require('../desktop-app/sandbox/isolation-backend-router.js');

const controller = new SandboxController({ autoCertify: false });
assert(controller.windowsBackend instanceof IsolationBackendRouter, 'SandboxController must default to the multi-backend isolation router');
assert.equal(controller.windowsBackend.prefer, 'windows-sandbox', 'certified Windows Sandbox must be preferred when available');
assert.deepEqual(controller.windowsBackend._order(), ['windows-sandbox', 'microvm', 'portable-vm']);
const initial = controller.certificationStatus();
assert.equal(initial.ok, false);
assert.equal(initial.state, 'not_run');
assert.equal(initial.isolationBackendReady, false);

const injected = {
  async capabilities() { return { available: false, releaseGrade: false }; },
  async runContainmentSelfTest() { return { ok: false, code: 'SYNTHETIC' }; },
  async runIsolationSelfTest() { return { ok: false, code: 'SYNTHETIC' }; },
  async analyze() { return { ok: false, verdict: 'inconclusive', code: 'SYNTHETIC' }; },
};
const compatible = new SandboxController({ windowsBackend: injected, autoCertify: false });
assert.strictEqual(compatible.windowsBackend, injected, 'legacy backend injection must remain supported');

console.log('✓ SandboxController default: Windows Sandbox first, MalGuard VM fallback router active, legacy injection preserved PASS');
