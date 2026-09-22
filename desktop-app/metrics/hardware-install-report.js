'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

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

function gpuVendor(name) {
  const value = String(name || '').toLowerCase();
  if (!value) return 'unknown';
  if (value.includes('nvidia')) return 'NVIDIA';
  if (value.includes('amd') || value.includes('radeon') || value.includes('advanced micro devices')) return 'AMD';
  if (value.includes('intel')) return 'Intel';
  if (value.includes('microsoft')) return 'Microsoft';
  return 'Other';
}

function safeDisplay(width, height) {
  const w = Number(width);
  const h = Number(height);
  if (!Number.isInteger(w) || !Number.isInteger(h) || w < 320 || h < 200 || w > 16384 || h > 16384) return 'unknown';
  return `${w}x${h}`;
}

function safeLanguage(value) {
  const text = String(value || '').trim();
  return /^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8}){0,2}$/.test(text) ? text : 'unknown';
}

function safeWindowsName(value) {
  const text = String(value || '').replace(/[^\x20-\x7E]/g, '').trim();
  if (!text || text.length > 80 || !/windows/i.test(text)) return 'Windows';
  return text;
}

function safeBuild(value) {
  const text = String(value || '').trim();
  return /^\d{3,10}$/.test(text) ? text : 'unknown';
}

function runWindowsProbe(execImpl = execFileSync) {
  const script = [
    "$ErrorActionPreference='Stop'",
    "$os=Get-CimInstance Win32_OperatingSystem",
    "$gpu=Get-CimInstance Win32_VideoController | Select-Object -First 1",
    "Add-Type -AssemblyName System.Windows.Forms",
    "$b=[System.Windows.Forms.Screen]::PrimaryScreen.Bounds",
    "$o=[pscustomobject]@{osName=$os.Caption;build=$os.BuildNumber;gpu=$gpu.Name;width=$b.Width;height=$b.Height;language=(Get-Culture).Name}",
    "$o | ConvertTo-Json -Compress"
  ].join(';');
  try {
    const raw = execImpl('powershell.exe', ['-NoLogo','-NoProfile','-NonInteractive','-Command',script], {
      encoding:'utf8',
      windowsHide:true,
      timeout:3000,
      maxBuffer:64 * 1024,
    });
    const parsed = JSON.parse(String(raw || '').trim());
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch (_) {
    return {};
  }
}

function collectHardwareProfile(options = {}) {
  const platform = options.platform || process.platform;
  if (platform !== 'win32') return null;
  const osImpl = options.osImpl || os;
  const arch = options.arch || process.arch;
  const probe = options.probe || runWindowsProbe(options.execImpl);

  return {
    schemaVersion:'1.0',
    event:'first_successful_launch',
    version:String(options.version || '').trim(),
    os:{
      name:safeWindowsName(probe.osName || 'Windows'),
      build:safeBuild(probe.build || osImpl.release()),
    },
    arch:arch === 'arm64' ? 'arm64' : arch === 'x64' ? 'x64' : arch === 'x86_64' ? 'x64' : 'unknown',
    cpuCoresBucket:bucketCpuCores((osImpl.cpus() || []).length),
    ramBucket:bucketRam(osImpl.totalmem()),
    gpuVendor:gpuVendor(probe.gpu),
    display:safeDisplay(probe.width, probe.height),
    language:safeLanguage(probe.language),
  };
}

function markerPath(settingsFile, version, arch) {
  const base = path.dirname(path.resolve(settingsFile));
  const safeVersion = String(version || '').replace(/[^0-9A-Za-z._-]/g, '_');
  const safeArch = String(arch || '').replace(/[^0-9A-Za-z._-]/g, '_');
  return path.join(base, 'metrics', `hardware-report-${safeVersion}-${safeArch}.sent.json`);
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

async function sendHardwareInstallReport(options = {}) {
  const disabled = options.disabled === true || process.env.MALGUARD_DISABLE_ANONYMOUS_HARDWARE_REPORT === '1';
  const ci = options.ci === true ? true : options.ci === false ? false : Boolean(process.env.CI || process.env.GITHUB_ACTIONS);
  const platform = options.platform || process.platform;
  const packageRoot = options.packageRoot || path.resolve(__dirname, '..', '..');
  const settingsFile = options.settingsFile;
  const fetchImpl = options.fetchImpl || globalThis.fetch;
  const endpoint = options.endpoint || ENDPOINT;

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

  const profile = collectHardwareProfile({
    platform,
    version:options.version,
    arch:options.arch || process.arch,
    osImpl:options.osImpl,
    probe:options.probe,
    execImpl:options.execImpl,
  });
  if (!profile || profile.arch === 'unknown' || !profile.version) return {ok:false,sent:false,reason:'invalid-profile'};

  const marker = markerPath(settingsFile, profile.version, profile.arch);
  if (await exists(marker)) return {ok:true,sent:false,reason:'already-sent'};

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), Number.isFinite(options.timeoutMs) ? options.timeoutMs : 5000);
  try {
    if (typeof fetchImpl !== 'function') throw new Error('fetch unavailable');
    const response = await fetchImpl(endpoint, {
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
  gpuVendor,
  safeDisplay,
  safeLanguage,
  collectHardwareProfile,
  markerPath,
  sendHardwareInstallReport,
};
