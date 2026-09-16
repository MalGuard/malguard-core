import assert from 'node:assert/strict';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { GtaProcessContainerRunner } = require('../desktop-app/sandbox/gta-processcontainer-runner.js');
const { validateTelemetry } = require('../desktop-app/sandbox/telemetry-validator.js');

function waitForChild(child) {
  return new Promise((resolve) => {
    let stdout = '';
    let stderr = '';
    child.stdout?.on('data', (chunk) => { if (stdout.length < 32768) stdout += chunk.toString('utf8'); });
    child.stderr?.on('data', (chunk) => { if (stderr.length < 32768) stderr += chunk.toString('utf8'); });
    child.once('error', (error) => resolve({ code: null, signal: null, error: error.message, stdout, stderr }));
    child.once('close', (code, signal) => resolve({ code, signal, error: null, stdout, stderr }));
  });
}

const fixtureExe = process.env.MALGUARD_GTA_VALIDATION_GAME_EXE;
const fixturePlugin = process.env.MALGUARD_GTA_VALIDATION_PLUGIN_DLL;
if (!fixtureExe || !fixturePlugin) throw new Error('GTA validation fixture paths are required');

const root = await fsp.mkdtemp(path.join(os.tmpdir(), 'malguard-gta-e2e-'));
const gameRoot = path.join(root, 'game-source');
const samplePath = path.join(root, 'HarmlessValidationPlugin.asi');
let session = null;

try {
  await fsp.mkdir(gameRoot, { recursive: true });
  await fsp.copyFile(fixtureExe, path.join(gameRoot, 'GTA5.exe'));
  await fsp.copyFile(fixturePlugin, samplePath);

  const runner = new GtaProcessContainerRunner({
    gameRoot,
    gameExecutable: 'GTA5.exe',
    observeSeconds: 8,
    gameStartupSeconds: 8,
    sessionRoot: path.join(root, 'sessions'),
  });

  const configured = await runner.configurationStatus();
  assert.equal(configured.ok, true, JSON.stringify(configured));
  const support = await runner.supportStatus();
  assert.equal(support.ok, true, JSON.stringify({ ...support, sdk: undefined }));

  session = await runner._prepareSession(samplePath, null, configured);
  const policy = runner.buildPolicy(session);
  assert.equal(policy.network.allowOutbound, false);
  assert.equal(policy.network.allowLocalNetwork, false);

  const containerConfig = support.sdk.createConfigFromPolicy(policy, 'process');
  containerConfig.process.commandLine = `${runner.buildCommand(session)} -ContextKind synthetic-gta-compatible`;
  containerConfig.process.cwd = session.runtimeGame;

  const child = support.sdk.spawnSandboxFromConfig(containerConfig, { usePty: false });
  const childResult = await waitForChild(child);

  const raw = JSON.parse((await fsp.readFile(session.resultPath, 'utf8')).replace(/^\uFEFF/, ''));
  const checked = validateTelemetry(raw, session.sessionId);
  assert.equal(checked.ok, true, JSON.stringify(checked));
  assert.equal(raw.networkPolicy, 'disabled-by-processcontainer');
  assert.equal(raw.execution.attempted, true);
  assert.equal(raw.execution.started, true);
  assert.equal(raw.gameContext.contextKind, 'synthetic-gta-compatible');
  assert.equal(raw.gameContext.syntheticFixture, true);
  assert.equal(raw.gameContext.realGame, false);
  assert.equal(raw.gameContext.fixtureStarted, true);
  assert.equal(raw.gameContext.containment, 'processcontainer');
  assert.equal(raw.gameContext.pluginObserved, true);

  const acceptance = {
    schemaVersion: '1.0.0',
    kind: 'malguard-gta-processcontainer-end-to-end-validation',
    ok: childResult.code === 0 && raw.execution.started === true && raw.gameContext.pluginObserved === true,
    syntheticGtaCompatibleFixture: true,
    actualGtaBinaryPresent: false,
    processContainerAvailable: support.ok === true,
    isolationTier: support.isolationTier || null,
    networkDeniedByPolicy: policy.network.allowOutbound === false && policy.network.allowLocalNetwork === false,
    ephemeralCloneUsed: true,
    pluginStagedAsAsi: session.sampleExtension === '.asi',
    pluginObservedInGameProcess: raw.gameContext.pluginObserved === true,
    telemetryValidated: checked.ok === true,
    childExitCode: childResult.code,
    childSignal: childResult.signal,
    remainingExternalGate: 'Actual GTA V binary and legitimate plugin loader are not installed on the GitHub runner.',
  };

  console.log(JSON.stringify(acceptance, null, 2));
  if (!acceptance.ok) {
    console.error('Process stderr:', childResult.stderr);
    process.exitCode = 20;
  }
} finally {
  if (session) await fsp.rm(session.root, { recursive: true, force: true }).catch(() => {});
  await fsp.rm(root, { recursive: true, force: true }).catch(() => {});
}
