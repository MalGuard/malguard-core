'use strict';

const assert = require('assert');
const { IsolationBackendRouter } = require('../desktop-app/sandbox/isolation-backend-router.js');
const server = require('../desktop-app/server.js');

(async () => {
  assert(server.sandbox, 'desktop server must expose sandbox controller');
  assert(server.sandbox.windowsBackend instanceof IsolationBackendRouter,
    'desktop server must use the multi-backend isolation router instead of pinning Windows Sandbox');

  const caps = await server.sandbox.windowsBackend.capabilities();
  assert.equal(caps.backend, 'malguard-isolation-router');
  assert.equal(caps.requiresWindowsSandbox, false);
  assert.equal(caps.windowsSandboxOptional, true);
  assert(Array.isArray(caps.fallbackOrder));
  assert(caps.fallbackOrder.includes('windows-sandbox'));
  assert(caps.fallbackOrder.includes('microvm'));
  assert(caps.fallbackOrder.includes('portable-vm'));

  console.log('✓ GTA Guard desktop sandbox uses the isolation router with fail-closed fallback support');
})().catch(error => {
  console.error(error);
  process.exit(1);
});
