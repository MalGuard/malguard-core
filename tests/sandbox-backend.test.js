'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { WindowsSandboxBackend } = require('../desktop-app/sandbox/windows-sandbox-backend.js');
const { SandboxController } = require('../desktop-app/sandbox/sandbox-controller.js');

(async () => {
  const backend = new WindowsSandboxBackend({ memoryMb: 2048, timeoutMs: 10000, observeSeconds: 5 });
  const caps = await backend.capabilities();
  assert.equal(caps.backend, 'windows-sandbox');
  assert.equal(caps.isolation.network, 'disabled');
  assert.equal(caps.isolation.clipboard, 'disabled');
  assert.equal(caps.isolation.mappedInput, 'read-only');
  assert.equal(caps.isolation.disposableVm, true);
  assert.equal(caps.isolation.cpuHardCap, false, 'native hard CPU quota remains an explicit acceptance blocker');
  assert.equal(caps.releaseGrade, false, 'backend must remain locked until Windows-native acceptance passes');

  const fakeSample = path.join('C:\\host&input', 'sample.exe');
  const xml = backend.buildWsbConfig({
    inputHost: { dir: 'C:\\host&input', samplePath: fakeSample },
    outputHost: 'C:\\host-output',
    sessionId: '00000000-0000-4000-8000-000000000000',
  });
  assert.match(xml, /<Networking>Disable<\/Networking>/);
  assert.match(xml, /<ClipboardRedirection>Disable<\/ClipboardRedirection>/);
  assert.match(xml, /<ReadOnly>true<\/ReadOnly>/);
  assert.match(xml, /<ProtectedClient>Enable<\/ProtectedClient>/);
  assert.match(xml, /C:\\host&amp;input/);
  assert.doesNotMatch(xml, /<Networking>Enable<\/Networking>/);

  const controller = new SandboxController({ windowsBackend: backend });
  const tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'malguard-sandbox-test-'));
  try {
    const samplePath = path.join(tempDir, 'synthetic.exe');
    await fs.promises.writeFile(samplePath, Buffer.from('MZ synthetic sandbox fixture'));
    const preflight = await controller.preflightSample(samplePath);
    assert.equal(preflight.ok, true);
    assert.equal(preflight.revalidated, true);
    assert.match(preflight.sha256, /^[a-f0-9]{64}$/);

    const denied = await controller.analyzeUntrustedSample(samplePath);
    assert.equal(denied.ok, false);
    assert.equal(denied.verdict, 'inconclusive');
    assert.equal(denied.code, 'WINDOWS_GUEST_EXECUTION_PROVIDER_UNAVAILABLE');
    assert.equal(denied.preflight.sha256, preflight.sha256);
    assert.equal(denied.sandboxLaunched, false);
    assert.equal(denied.sampleExecutionStarted, false);
  } finally {
    await fs.promises.rm(tempDir, { recursive: true, force: true });
  }

  console.log('✓ Sandbox backend: portable isolation core plus fail-closed Windows guest provider policy PASS');
})().catch(error => {
  console.error(error.stack || error);
  process.exit(1);
});
