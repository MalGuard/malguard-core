'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { WindowsSandboxBackend } = require('../desktop-app/sandbox/windows-sandbox-backend.js');
const { SandboxController } = require('../desktop-app/sandbox/sandbox-controller.js');

(async () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'native', 'sandbox-containment-probe', 'MalGuardSandboxContainmentProbe.cpp'), 'utf8');
  assert.match(source, /JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP/);
  assert.match(source, /JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE/);
  assert.match(source, /JOB_OBJECT_LIMIT_PROCESS_MEMORY/);
  assert.match(source, /CREATE_SUSPENDED/);
  assert.match(source, /AssignProcessToJobObject/);
  assert.match(source, /ResumeThread/);
  assert.match(source, /TerminateJobObject/);
  assert.match(source, /GetModuleFileNameW\(nullptr/);
  assert.match(source, /--child-busy/);
  assert.doesNotMatch(source, /argv\[2\]/, 'containment probe must not accept an arbitrary executable path');

  const backend = new WindowsSandboxBackend();
  const config = backend.buildIsolationSelfTestConfig({
    inputHost: 'C:\\MalGuardSelfTestInput',
    outputHost: 'C:\\MalGuardSelfTestOutput',
    sessionId: '00000000-0000-4000-8000-000000000000',
  });
  assert.match(config, /<Networking>Disable<\/Networking>/);
  assert.match(config, /<ClipboardRedirection>Disable<\/ClipboardRedirection>/);
  assert.match(config, /<ReadOnly>true<\/ReadOnly>/);
  assert.match(config, /self-test-harness\.ps1/);
  assert.doesNotMatch(config, /sample\.exe/i, 'isolation self-test must not detonate a sample');

  if (process.platform !== 'win32') {
    assert.equal((await backend.runContainmentSelfTest()).code, 'CONTAINMENT_PROBE_UNSUPPORTED_HOST');
    assert.equal((await backend.runIsolationSelfTest()).code, 'WINDOWS_SANDBOX_UNAVAILABLE');
  }

  const controller = new SandboxController({ windowsBackend: backend });
  const report = await controller.selfTest();
  assert.equal(report.localProbe.ok, true);
  assert.equal(report.releaseReady, false);
  assert(Array.isArray(report.blockers) && report.blockers.length >= 1);

  console.log('✓ Sandbox native containment probe source and synthetic Windows isolation validation path PASS');
})().catch(error => {
  console.error(error.stack || error);
  process.exit(1);
});
