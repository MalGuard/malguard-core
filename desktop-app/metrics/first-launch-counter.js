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
  const version = options.version;
  const arch = options.arch || process.arch;
  const platform = options.platform || process.platform;
  const settingsFile = options.settingsFile;
  const packageRoot = options.packageRoot || path.resolve(__dirname, '..', '..');
  const fetchImpl = options.fetchImpl || globalThis.fetch;
  const timeoutMs = Number.isFinite(options.timeoutMs) ? options.timeoutMs : 5000;
  const disabled = options.disabled === true || process.env.MALGUARD_DISABLE_ANONYMOUS_INSTALL_COUNT === '1';
  const ci = options.ci === true ? true : options.ci === false ? false : Boolean(process.env.CI || process.env.GITHUB_ACTIONS);

  if (disabled) return { ok: true, counted: false, reason: 'disabled' };
  if (ci) return { ok: true, counted: false, reason: 'ci' };
  if (platform !== 'win32') return { ok: true, counted: false, reason: 'non-windows' };
  if (!settingsFile) return { ok: false, counted: false, reason: 'settings-file-required' };
  if (!packagedRuntimeExists(packageRoot) && options.requirePackaged !== false) {
    return { ok: true, counted: false, reason: 'source-checkout' };
  }

  const url = buildBeaconUrl(version, arch);
  if (!url) return { ok: true, counted: false, reason: 'unsupported-architecture' };

  const markers = markerPaths(settingsFile, version, arch);
  await fs.promises.mkdir(markers.root, { recursive: true, mode: 0o700 });

  if (await fileExists(markers.counted)) return { ok: true, counted: false, reason: 'already-counted' };
  if (await fileExists(markers.pending)) {
    return { ok: true, counted: false, reason: 'prior-attempt-pending' };
  }

  await writePrivateJson(markers.pending, {
    schemaVersion: '1.0.0',
    state: 'pending',
    version,
    architecture: arch,
    createdAt: Date.now(),
  });

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), Math.max(1, timeoutMs));

  try {
    if (typeof fetchImpl !== 'function') throw new Error('fetch unavailable');
    const response = await fetchImpl(url, {
      method: 'GET',
      redirect: 'follow',
      cache: 'no-store',
      signal: controller.signal,
    });

    if (!response || response.ok !== true) {
      throw new Error(`beacon request failed: ${response ? response.status : 'no response'}`);
    }

    const finalUrl = new URL(response.url || url);
    if (!ALLOWED_FINAL_HOSTS.has(finalUrl.hostname)) {
      throw new Error('beacon redirected to an unexpected host');
    }

    if (typeof response.arrayBuffer === 'function') await response.arrayBuffer();

    await fs.promises.rename(markers.pending, markers.counted);
    return { ok: true, counted: true, reason: 'counted' };
  } catch (_) {
    try { await fs.promises.unlink(markers.pending); } catch (_) {}
    return { ok: false, counted: false, reason: 'network-failed' };
  } finally {
    clearTimeout(timer);
  }
}

module.exports = {
  buildBeaconUrl,
  markerPaths,
  recordFirstSuccessfulLaunch,
};
