'use strict';

const fs = require('fs');
const path = require('path');

const RELEASE_OWNER = 'MalGuard';
const RELEASE_REPO = 'malguard.github.io';
const SUPPORTED_ARCHES = new Set(['x64', 'arm64']);
const ALLOWED_FINAL_HOSTS = new Set([
  'github.com',
  'release-assets.githubusercontent.com',
  'objects.githubusercontent.com',
]);

function safeToken(value, field) {
  const text = String(value || '').trim();
  if (!text || !/^[0-9A-Za-z._-]+$/.test(text)) {
    throw new Error(`invalid ${field}`);
  }
  return text;
}

function buildBeaconUrl(version, arch) {
  const safeVersion = safeToken(version, 'version');
  const safeArch = safeToken(arch, 'architecture');
  if (!SUPPORTED_ARCHES.has(safeArch)) return null;
  const tag = `downloads-v${safeVersion}`;
  const asset = `MalGuard-install-beacon-${safeVersion}-windows-${safeArch}.txt`;
  return `https://github.com/${RELEASE_OWNER}/${RELEASE_REPO}/releases/download/${tag}/${asset}`;
}

function markerPaths(settingsFile, version, arch) {
  const root = path.join(path.dirname(path.resolve(settingsFile)), 'metrics');
  const stem = `first-successful-launch-${safeToken(version, 'version')}-${safeToken(arch, 'architecture')}`;
  return {
    root,
    pending: path.join(root, `${stem}.pending.json`),
    counted: path.join(root, `${stem}.counted.json`),
  };
}

async function fileExists(filePath) {
  try {
    await fs.promises.access(filePath, fs.constants.F_OK);
    return true;
  } catch (_) {
    return false;
  }
}

async function writePrivateJson(filePath, value) {
  const tmp = `${filePath}.${process.pid}.tmp`;
  await fs.promises.writeFile(tmp, JSON.stringify(value, null, 2), {
    encoding: 'utf8',
    flag: 'wx',
    mode: 0o600,
  });
  await fs.promises.rename(tmp, filePath);
}

function packagedRuntimeExists(packageRoot) {
  try {
    return fs.statSync(path.join(path.resolve(packageRoot), 'PACKAGE-MANIFEST.json')).isFile();
  } catch (_) {
    return false;
  }
}

async function recordFirstSuccessfulLaunch(options = {}) {
  // Retired: diagnostics are sent only through TelemetryClient and its central gate.
  const allowed = options.consent?.canSendDiagnostics() === true;
  return { ok:true, counted:false, reason:allowed ? 'legacy-retired' : 'consent-required' };
}

module.exports = {
  buildBeaconUrl,
  markerPaths,
  recordFirstSuccessfulLaunch,
};
