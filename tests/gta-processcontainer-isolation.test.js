'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { SandboxController } = require('../desktop-app/sandbox/sandbox-controller.js');
const { GtaProcessContainerRunner } = require('../desktop-app/sandbox/gta-processcontainer-runner.js');
const { validateTelemetry } = require('../desktop-app/sandbox/telemetry-validator.js');

(async () => {
  const root = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'malguard-gta-pc-test-'));
  try {
    const gameRoot = path.join(root, 'game');
    await fs.promises.mkdir(gameRoot, { recursive: true });
    await fs.promises.writeFile(path.join(gameRoot, 'GTA5.exe'), 'synthetic-gta-fixture');
    const samplePath = path.join(root, 'sample.dll');
    await fs.promises.writeFile(samplePath, 'synthetic-plugin-fixture');

    const runner = new GtaProcessContainerRunner({
      gameRoot,
      gameExecutable: 'GTA5.exe',
      sdkLoader: async () => ({
        getPlatformSupport: () => ({
          isSupported: true,
          availableMethods: ['processcontainer'],
          isolationTier: 'process',
          isolationWarnings: [],
        }),
      }),
    });

    const config = await runner.configurationStatus();
    assert.equal(config.ok, true);
    assert.equal(config.requiresNestedVirtualization, false);
    assert.equal(config.hostGameReadOnly, true);
    assert.equal(config.stagingMode, 'host-created-ephemeral-game-clone');

    const support = await runner.supportStatus();
    if (process.platform === 'win32') {
      assert.equal(support.ok, true);
      assert.equal(support.requiresNestedVirtualization, false);
    } else {
      assert.equal(support.ok, false);
      assert.equal(support.code, 'GTA_PROCESSCONTAINER_WINDOWS_REQUIRED');
    }

    const fakeSession = {
      inputDir: path.join(root, 'input'),
      runtimeRoot: path.join(root, 'runtime'),
      outputDir: path.join(root, 'output'),
    };
    const policy = runner.buildPolicy(fakeSession);
    assert.deepEqual(policy.filesystem.readonlyPaths, [fakeSession.inputDir]);
    assert(policy.filesystem.readwritePaths.includes(fakeSession.runtimeRoot));
    assert(policy.filesystem.readwritePaths.includes(fakeSession.outputDir));
    assert.equal(policy.network.allowOutbound, false);
    assert.equal(policy.network.allowLocalNetwork, false);
    assert.equal(Object.prototype.hasOwnProperty.call(policy.network, 'egress'), false);
    assert.equal(Object.prototype.hasOwnProperty.call(policy.network, 'ingress'), false);

    const telemetry = {
      schemaVersion: '1.1.0',
      sessionId: 'pc-test-session',
      startedAt: '2026-09-16T00:00:00.000Z',
      finishedAt: '2026-09-16T00:00:01.000Z',
      networkPolicy: 'disabled-by-processcontainer',
      execution: {
        attempted: true,
        started: true,
        exitCode: 0,
        timedOut: false,
        cpuBudgetExceeded: false,
        outputQuotaExceeded: false,
        error: null,
      },
      baselineProcesses: [],
      finalProcesses: [],
      recentFiles: [],
    };
    const checked = validateTelemetry(telemetry, 'pc-test-session');
    assert.equal(checked.ok, true);
    assert.equal(checked.telemetry.networkPolicy, 'disabled-by-processcontainer');

    let processContainerCalls = 0;
    const fakeProcessContainer = {
      supportStatus: async () => ({ ok: true, code: 'GTA_PROCESSCONTAINER_AVAILABLE', requiresNestedVirtualization: false }),
      configurationStatus: async () => ({ ok: true, realGame: true, gameRoot, gameExecutable: 'GTA5.exe' }),
      analyze: async () => {
        processContainerCalls += 1;
        return {
          ok: true,
          verdict: 'inconclusive',
          telemetry: { execution: { attempted: true, started: true } },
          gameContext: { realGame: true, proven: true },
        };
      },
    };

    let windowsAnalyzeCalls = 0;
    const fakeWindowsBackend = {
      capabilities: async () => ({ available: false, releaseGrade: false }),
      executablePath: () => 'WindowsSandbox.exe',
      analyze: async () => { windowsAnalyzeCalls += 1; return { ok: false }; },
      runContainmentSelfTest: async () => ({ ok: false, code: 'NOT_USED' }),
      runIsolationSelfTest: async () => ({ ok: false, code: 'NOT_USED' }),
    };

    const controller = new SandboxController({
      windowsBackend: fakeWindowsBackend,
      processContainerRunner: fakeProcessContainer,
      gtaContextRunner: { configurationStatus: async () => ({ ok: false }) },
    });
    const result = await controller.analyzeUntrustedSample(samplePath);
    assert.equal(processContainerCalls, 1, 'ProcessContainer must be preferred when available');
    assert.equal(windowsAnalyzeCalls, 0, 'Windows Sandbox fallback must not run when ProcessContainer succeeds');
    assert.equal(result.ok, true);
    assert.equal(result.isolation, 'processcontainer');
    assert.equal(result.requiresNestedVirtualization, false);
    assert.equal(result.sandboxLaunched, true);
    assert.equal(result.sampleExecutionStarted, true);

    console.log('✓ GTA ProcessContainer isolation: no nested virtualization dependency, live-validated MXC network deny policy, ProcessContainer-first routing, and telemetry policy PASS');
  } finally {
    await fs.promises.rm(root, { recursive: true, force: true });
  }
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
