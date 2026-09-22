'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

const ENDPOINT = 'https://malguard-core-sandbox.vercel.app/api/install-hardware-report';

function bucketCpuCores(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) return 'unknown';
  if (n <= 4) return '1-4';
  if (n <= 8) return '5-8';
  if (n <= 12) return '9-12';
  if (n <= 16) return '13-16';
  if (n <= 24) return '17-24';
  return '25+';
}

function bucketRam(bytes) {
  const gib = Number(bytes) / (1024 ** 3);
  if (!Number.isFinite(gib) || gib <= 0) return 'unknown';
  if (gib < 4) return '<4 GB';
  if (gib < 8) return '4-8 GB';
  if (gib < 16) return '8-16 GB';
  if (gib < 32) return '16-32 GB';
  if (gib < 64) return '32-64 GB';
  return '64+ GB';
}

function windowsBuild(release) {
  const text = String(release || '').trim();
  const parts = text.split('.');
  const build = parts.length >= 3 ? parts[2] : text;
  return /^\d{3,10}$/.test(build) ? build : 'unknown';
}

function systemLanguage() {
  try {
    const value = Intl.DateTimeFormat().resolvedOptions().locale;
    return /^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8}){0,2}$/.test(value) ? value : 'unknown';
  } catch (_) {
    return 'unknown';
  }
}

function collectCompatibilityProfile(options = {}) {
  const platform = options.platform || process.platform;
  if (platform !== 'win32') return null;
  const osImpl = options.osImpl || os;
  const arch = options.arch || process.arch;
  const release = osImpl.release();
  return {
    schemaVersion:'1.0',
    event:'first_successful_launch',
    version:String(options.version || '').trim(),
    os:'Windows',
    build:windowsBuild(release),
    arch:arch === 'arm64' ? 'arm64' : arch === 'x64' || arch === 'x86_64' ? 'x64' : 'unknown',
    cpuCoresBucket:bucketCpuCores((osImpl.cpus() || []).length),
    ramBucket:bucketRam(osImpl.totalmem()),
    language:String(options.language || systemLanguage()),
  };
}

function markerPath(settingsFile, version, arch) {
  const base = path.dirname(path.resolve(settingsFile));
  const safeVersion = String(version || '').replace(/[^0-9A-Za-z._-]/g, '_');
  const safeArch = String(arch || '').replace(/[^0-9A-Za-z._-]/g, '_');
  return path.join(base, 'metrics', `compatibility-report-${safeVersion}-${safeArch}.sent.json`);
}

async function exists(file) {
  try { await fs.promises.access(file); return true; } catch (_) { return false; }
}

async function writeMarker(file, payload) {
  await fs.promises.mkdir(path.dirname(file), { recursive:true, mode:0o700 });
  const tmp = `${file}.${process.pid}.tmp`;
  await fs.promises.writeFile(tmp, JSON.stringify(payload, null, 2), { encoding:'utf8', flag:'wx', mode:0o600 });
  await fs.promises.rename(tmp, file);
}

async function sendCompatibilityInstallReport(options = {}) {
  const disabled = options.disabled === true || process.env.MALGUARD_DISABLE_ANONYMOUS_COMPATIBILITY_REPORT === '1';
  const ci = options.ci === true ? true : options.ci === false ? false : Boolean(process.env.CI || process.env.GITHUB_ACTIONS);
  const platform = options.platform || process.platform;
  const packageRoot = options.packageRoot || path.resolve(__dirname, '..', '..');
  const settingsFile = options.settingsFile;
  const fetchImpl = options.fetchImpl || globalThis.fetch;

  if (disabled) return {ok:true,sent:false,reason:'disabled'};
  if (ci) return {ok:true,sent:false,reason:'ci'};
  if (platform !== 'win32') return {ok:true,sent:false,reason:'non-windows'};
  if (!settingsFile) return {ok:false,sent:false,reason:'settings-file-required'};

  if (options.requirePackaged !== false) {
    try {
      if (!fs.statSync(path.join(packageRoot, 'PACKAGE-MANIFEST.json')).isFile()) return {ok:true,sent:false,reason:'source-checkout'};
    } catch (_) {
      return {ok:true,sent:false,reason:'source-checkout'};
    }
  }

  const profile = collectCompatibilityProfile({
    platform,
    version:options.version,
    arch:options.arch || process.arch,
    osImpl:options.osImpl,
    language:options.language,
  });
  if (!profile || profile.arch === 'unknown' || !profile.version) return {ok:false,sent:false,reason:'invalid-profile'};

  const marker = markerPath(settingsFile, profile.version, profile.arch);
  if (await exists(marker)) return {ok:true,sent:false,reason:'already-sent'};

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), Number.isFinite(options.timeoutMs) ? options.timeoutMs : 5000);
  try {
    if (typeof fetchImpl !== 'function') throw new Error('fetch unavailable');
    const response = await fetchImpl(options.endpoint || ENDPOINT, {
      method:'POST',
      headers:{'content-type':'application/json'},
      body:JSON.stringify(profile),
      redirect:'error',
      signal:controller.signal,
    });
    if (!response || response.ok !== true) return {ok:false,sent:false,reason:'server-rejected'};
    await writeMarker(marker, {schemaVersion:'1.0',sentAt:Date.now(),version:profile.version,architecture:profile.arch});
    return {ok:true,sent:true,reason:'sent'};
  } catch (_) {
    return {ok:false,sent:false,reason:'network-failed'};
  } finally {
    clearTimeout(timer);
  }
}

module.exports = {
  ENDPOINT,
  bucketCpuCores,
  bucketRam,
  windowsBuild,
  collectCompatibilityProfile,
  markerPath,
  sendCompatibilityInstallReport,
};
