'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {
  buildBeaconUrl,
  markerPaths,
  recordFirstSuccessfulLaunch,
} = require('../desktop-app/metrics/first-launch-counter.js');

(async () => {
  assert.strictEqual(
    buildBeaconUrl('0.6.1-beta.1', 'x64'),
    'https://github.com/MalGuard/malguard.github.io/releases/download/downloads-v0.6.1-beta.1/MalGuard-install-beacon-0.6.1-beta.1-windows-x64.txt'
  );
  assert.strictEqual(buildBeaconUrl('0.6.1-beta.1', 'ia32'), null);

  const tmp = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'malguard-install-count-'));
  const settingsFile = path.join(tmp, 'settings.json');
  let calls = 0;
  const fetchImpl = async () => {
    calls += 1;
    return {
      ok: true,
      status: 200,
      url: 'https://release-assets.githubusercontent.com/fake/beacon',
      arrayBuffer: async () => new ArrayBuffer(0),
    };
  };

  const first = await recordFirstSuccessfulLaunch({
    version: '0.6.1-beta.1',
    arch: 'x64',
    platform: 'win32',
    settingsFile,
    packageRoot: tmp,
    requirePackaged: false,
    ci: false,
    disabled: false,
    fetchImpl,
  });
  assert.strictEqual(first.ok, true);
  assert.strictEqual(first.counted, true);
  assert.strictEqual(calls, 1);

  const markers = markerPaths(settingsFile, '0.6.1-beta.1', 'x64');
  assert.strictEqual(await fs.promises.stat(markers.counted).then(() => true, () => false), true);
  assert.strictEqual(await fs.promises.stat(markers.pending).then(() => true, () => false), false);

  const second = await recordFirstSuccessfulLaunch({
    version: '0.6.1-beta.1',
    arch: 'x64',
    platform: 'win32',
    settingsFile,
    packageRoot: tmp,
    requirePackaged: false,
    ci: false,
    disabled: false,
    fetchImpl,
  });
  assert.strictEqual(second.counted, false);
  assert.strictEqual(second.reason, 'already-counted');
  assert.strictEqual(calls, 1);

  const failedRoot = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'malguard-install-count-fail-'));
  const failedSettings = path.join(failedRoot, 'settings.json');
  const failed = await recordFirstSuccessfulLaunch({
    version: '0.6.1-beta.1',
    arch: 'x64',
    platform: 'win32',
    settingsFile: failedSettings,
    packageRoot: failedRoot,
    requirePackaged: false,
    ci: false,
    disabled: false,
    fetchImpl: async () => ({ ok: false, status: 503, url: 'https://github.com/' }),
  });
  assert.strictEqual(failed.ok, false);
  assert.strictEqual(failed.counted, false);
  const failedMarkers = markerPaths(failedSettings, '0.6.1-beta.1', 'x64');
  assert.strictEqual(await fs.promises.stat(failedMarkers.pending).then(() => true, () => false), false);

  let disabledCalls = 0;
  const disabled = await recordFirstSuccessfulLaunch({
    version: '0.6.1-beta.1',
    arch: 'x64',
    platform: 'win32',
    settingsFile: path.join(tmp, 'disabled-settings.json'),
    packageRoot: tmp,
    requirePackaged: false,
    ci: false,
    disabled: true,
    fetchImpl: async () => { disabledCalls += 1; throw new Error('must not be called'); },
  });
  assert.strictEqual(disabled.reason, 'disabled');
  assert.strictEqual(disabledCalls, 0);

  const sourceCheckout = await recordFirstSuccessfulLaunch({
    version: '0.6.1-beta.1',
    arch: 'x64',
    platform: 'win32',
    settingsFile: path.join(tmp, 'source-settings.json'),
    packageRoot: tmp,
    ci: false,
    disabled: false,
    fetchImpl,
  });
  assert.strictEqual(sourceCheckout.reason, 'source-checkout');

  await fs.promises.rm(tmp, { recursive: true, force: true });
  await fs.promises.rm(failedRoot, { recursive: true, force: true });
  console.log('✓ privacy-preserving first successful launch counter');
})().catch(error => {
  console.error(error);
  process.exit(1);
});
