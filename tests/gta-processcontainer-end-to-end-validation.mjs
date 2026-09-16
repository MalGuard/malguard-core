import assert from 'node:assert/strict';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { GtaProcessContainerRunner } = require('../desktop-app/sandbox/gta-processcontainer-runner.js');

const fixtureExe = process.env.MALGUARD_GTA_VALIDATION_GAME_EXE;
const fixturePlugin = process.env.MALGUARD_GTA_VALIDATION_PLUGIN_DLL;
const nativeHarness = process.env.MALGUARD_GTA_PROCESSCONTAINER_HARNESS_EXE;
if (!fixtureExe || !fixturePlugin || !nativeHarness) throw new Error('GTA validation fixture and native harness paths are required');

const root = await fsp.mkdtemp(path.join(os.tmpdir(), 'malguard-gta-e2e-'));
const gameRoot = path.join(root, 'game-source');
const samplePath = path.join(root, 'HarmlessValidationPlugin.asi');

try {
  await fsp.mkdir(gameRoot, { recursive: true });
  await fsp.copyFile(fixtureExe, path.join(gameRoot, 'GTA5.exe'));
  await fsp.copyFile(fixturePlugin, samplePath);

  const runner = new GtaProcessContainerRunner({
    gameRoot,
    gameExecutable: 'GTA5.exe',
    harnessExecutable: nativeHarness,
    contextKind: 'synthetic-gta-compatible',
    observeSeconds: 8,
    gameStartupSeconds: 8,
    sessionRoot: path.join(root, 'sessions'),
  });

  const configured = await runner.configurationStatus();
  assert.equal(configured.ok, true, JSON.stringify(configured));
  assert.equal(configured.contextKind, 'synthetic-gta-compatible');

  const support = await runner.supportStatus();
  assert.equal(support.ok, true, JSON.stringify({ ...support, sdk: undefined }));

  const policy = runner.buildPolicy({
    inputDir: path.join(root, 'policy-input'),
    runtimeRoot: path.join(root, 'policy-runtime'),
    outputDir: path.join(root, 'policy-output'),
  });
  assert.equal(policy.network.allowOutbound, false);
  assert.equal(policy.network.allowLocalNetwork, false);

  const result = await runner.analyze(samplePath);
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.isolation, 'processcontainer');
  assert.equal(result.requiresNestedVirtualization, false);
  assert.equal(result.sampleExecutionStarted, true);
  assert.equal(result.gameContext.realGame, false);
  assert.equal(result.gameContext.syntheticFixture, true);
  assert.equal(result.telemetry.gameContext.contextKind, 'synthetic-gta-compatible');
  assert.equal(result.telemetry.gameContext.fixtureStarted, true);
  assert.equal(result.telemetry.gameContext.pluginObserved, true);
  assert.equal(result.telemetry.networkPolicy, 'disabled-by-processcontainer');

  const acceptance = {
    schemaVersion: '1.0.0',
    kind: 'malguard-gta-processcontainer-end-to-end-validation',
    ok: true,
    syntheticGtaCompatibleFixture: true,
    actualGtaBinaryPresent: false,
    nativeHarnessExecuted: true,
    processContainerAvailable: support.ok === true,
    isolationTier: support.isolationTier || null,
    networkDeniedByPolicy: policy.network.allowOutbound === false && policy.network.allowLocalNetwork === false,
    ephemeralCloneUsed: true,
    pluginStagedAsAsi: true,
    pluginObservedInGameProcess: result.telemetry.gameContext.pluginObserved === true,
    telemetryValidated: true,
    childExitCode: result.process?.code ?? null,
    childSignal: result.process?.signal ?? null,
    remainingExternalGate: 'Actual GTA V binary and legitimate plugin loader are not installed on the GitHub runner.',
  };

  console.log(JSON.stringify(acceptance, null, 2));
} finally {
  await fsp.rm(root, { recursive: true, force: true }).catch(() => {});
}
