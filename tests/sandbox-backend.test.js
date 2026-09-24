'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { WindowsSandboxBackend, DEFAULT_SANDBOX_TIMEOUT_MS, ISOLATION_SELF_TEST_TIMEOUT_MS } = require('../desktop-app/sandbox/windows-sandbox-backend.js');
const { SandboxController } = require('../desktop-app/sandbox/sandbox-controller.js');

(async () => {
  assert.equal(DEFAULT_SANDBOX_TIMEOUT_MS, 60000, 'default behavioral Sandbox launch timeout must allow slow Windows hosts');
  assert.equal(ISOLATION_SELF_TEST_TIMEOUT_MS, 60000, 'isolation self-test timeout must allow slow Windows Sandbox startup');
  const defaultBackend = new WindowsSandboxBackend();
  assert.equal(defaultBackend.timeoutMs, 60000);
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

  const controller = new SandboxController({ windowsBackend: backend, allowExperimentalDetonation: false });
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
    assert(['WINDOWS_SANDBOX_UNAVAILABLE', 'HARDENED_SANDBOX_ACCEPTANCE_PENDING'].includes(denied.code));
    assert.equal(denied.preflight.sha256, preflight.sha256);
  } finally {
    await fs.promises.rm(tempDir, { recursive: true, force: true });
  }

  console.log('✓ Sandbox backend: Windows Sandbox isolation config and release-path fail-closed policy PASS');
})().catch(error => {
  console.error(error.stack || error);
  process.exit(1);
});
