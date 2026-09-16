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
const externalLoader = process.env.MALGUARD_GTA_EXTERNAL_ASI_LOADER_DLL;
const expectedLoaderSha256 = (process.env.MALGUARD_GTA_EXTERNAL_ASI_LOADER_SHA256 || '').toLowerCase();
if (!fixtureExe || !fixturePlugin || !nativeHarness || !externalLoader || !expectedLoaderSha256) {
  throw new Error('external ASI loader validation inputs are required');
}

const crypto = await import('node:crypto');
async function sha256(filePath) {
  const data = await fsp.readFile(filePath);
  return crypto.createHash('sha256').update(data).digest('hex');
}

const hostSource = await fsp.readFile(
  new URL('../native/gta-validation-fixture/GtaExternalAsiLoaderHost.cpp', import.meta.url),
  'utf8',
);
assert.equal(/LoadLibrary(?:A|W)?\s*\(/i.test(hostSource), false, 'external-loader fixture must not load the ASI itself');
assert.equal((await sha256(externalLoader)).toLowerCase(), expectedLoaderSha256, 'external ASI loader hash mismatch');

const root = await fsp.mkdtemp(path.join(os.tmpdir(), 'malguard-gta-ual-'));
const gameRoot = path.join(root, 'game-source');
const samplePath = path.join(root, 'HarmlessValidationPlugin.asi');

try {
  await fsp.mkdir(gameRoot, { recursive: true });
  await fsp.copyFile(fixtureExe, path.join(gameRoot, 'GTA5.exe'));
  await fsp.copyFile(externalLoader, path.join(gameRoot, 'dinput8.dll'));
  await fsp.writeFile(
    path.join(gameRoot, 'dinput8.ini'),
    '[GlobalSets]\r\nLoadPlugins=1\r\nLoadFromScriptsOnly=0\r\nDontLoadFromDllMain=0\r\n',
    'utf8',
  );
  await fsp.copyFile(fixturePlugin, samplePath);

  const runner = new GtaProcessContainerRunner({
    gameRoot,
    gameExecutable: 'GTA5.exe',
    harnessExecutable: nativeHarness,
    contextKind: 'synthetic-gta-compatible',
    observeSeconds: 10,
    gameStartupSeconds: 10,
    sessionRoot: path.join(root, 'sessions'),
  });

  const support = await runner.supportStatus();
  assert.equal(support.ok, true, JSON.stringify({ ...support, sdk: undefined }));

  const result = await runner.analyze(samplePath);
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.isolation, 'processcontainer');
  assert.equal(result.telemetry.gameContext.pluginObserved, true);
  assert.equal(result.telemetry.networkPolicy, 'disabled-by-processcontainer');

  const finalModules = Array.isArray(result.telemetry.gameContext.finalModules)
    ? result.telemetry.gameContext.finalModules
    : [];
  const loaderObserved = finalModules.some((module) => {
    const name = String(module.ModuleName ?? module.moduleName ?? '').toLowerCase();
    const file = String(module.FileName ?? module.fileName ?? '').toLowerCase();
    return name === 'dinput8.dll' || file.endsWith('\\dinput8.dll') || file.endsWith('/dinput8.dll');
  });
  assert.equal(loaderObserved, true, 'real external dinput8 ASI loader was not observed in the game-context process');

  const acceptance = {
    schemaVersion: '1.0.0',
    kind: 'malguard-gta-external-asi-loader-processcontainer-validation',
    ok: true,
    actualGtaBinaryPresent: false,
    simulatorHost: 'MalGuard GTA-compatible native host',
    externalAsiLoader: 'ThirteenAG Ultimate ASI Loader v9.7.0',
    externalLoaderSha256: expectedLoaderSha256,
    externalLoaderObservedInGameProcess: loaderObserved,
    pluginObservedInGameProcess: result.telemetry.gameContext.pluginObserved === true,
    processContainerAvailable: support.ok === true,
    isolationTier: support.isolationTier || null,
    networkDenied: result.telemetry.networkPolicy === 'disabled-by-processcontainer',
    directPluginLoadByFixture: false,
    loaderConfiguration: 'LoadPlugins=1; LoadFromScriptsOnly=0; DontLoadFromDllMain=0',
    remainingExternalGate: 'This validates a real third-party ASI loader against the GTA-compatible simulator; it is not a claim that Rockstar GTA V itself was executed.',
  };

  console.log(JSON.stringify(acceptance, null, 2));
} finally {
  await fsp.rm(root, { recursive: true, force: true, maxRetries: 6, retryDelay: 75 }).catch(() => {});
}
