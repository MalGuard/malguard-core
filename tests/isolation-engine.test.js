'use strict';

const assert = require('assert');
const { IsolationEngine } = require('../desktop-app/sandbox/isolation-engine.js');

(async () => {
  const unavailableBackend = {
    async capabilities() {
      return { backend: 'windows-sandbox', available: false, releaseGrade: false };
    },
  };
  const engine = new IsolationEngine({ windowsBackend: unavailableBackend });
  const core = engine.coreCapabilities();
  assert.equal(core.coreReady, true);
  assert.equal(core.hostExecutionAllowed, false);
  assert.equal(core.policy.untrustedExecutionOnHost, 'forbidden');
  assert.equal(core.policy.failClosed, true);
  assert.equal(core.policy.inputMapping, 'read-only');
  assert.equal(core.policy.guestLifetime, 'ephemeral');
  assert.equal(core.policy.networkDefault, 'disabled');

  const unavailable = await engine.runtimeCapabilities({ executionCertified: false });
  assert.equal(unavailable.coreReady, true);
  assert.equal(unavailable.behavioralExecutionReady, false);
  assert.equal(unavailable.windowsGuestProvider.available, false);

  const denied = await engine.selectProvider({ extension: '.exe' }, { executionCertified: false });
  assert.equal(denied.ok, false);
  assert.equal(denied.code, 'WINDOWS_GUEST_EXECUTION_PROVIDER_UNAVAILABLE');

  const readyBackend = {
    async capabilities() {
      return { backend: 'windows-sandbox', available: true, releaseGrade: true };
    },
  };
  const readyEngine = new IsolationEngine({ windowsBackend: readyBackend });
  const selected = await readyEngine.selectProvider({ extension: '.exe' }, { executionCertified: true });
  assert.equal(selected.ok, true);
  assert.equal(selected.provider, 'windows-sandbox');
  assert.equal(selected.runtime.behavioralExecutionReady, true);

  const unsupported = await readyEngine.selectProvider({ extension: '.elf' }, { executionCertified: true });
  assert.equal(unsupported.ok, false);
  assert.equal(unsupported.code, 'ISOLATION_GUEST_TYPE_UNSUPPORTED');

  console.log('✓ MalGuard Isolation Engine: host execution forbidden, core portability and provider gating PASS');
})().catch(error => {
  console.error(error.stack || error);
  process.exit(1);
});
