'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const DEFAULT_BIN = path.join(__dirname, 'bin');
const DEFAULT_RULES = path.join(__dirname, 'rules', 'malguard.yar');
const BUNDLE_MARKER = 'ENGINE-BUNDLE.json';
const MAX_FILE_SIZE = 64 * 1024 * 1024;
const MAX_OUTPUT = 32 * 1024 * 1024;
const PE_EXTENSIONS = new Set(['.asi', '.dll', '.exe']);
const SUPPORTED_EXTENSIONS = new Set(['.asi', '.dll', '.exe', '.lua', '.cs', '.zip']);

function safeJson(text) {
  try { return JSON.parse(String(text || '')); } catch (_) { return null; }
}
function boundedText(value, max = 16384) {
  const text = String(value || '');
  return text.length > max ? text.slice(0, max) : text;
}
function runTool(spawn, exe, args, timeoutMs) {
  const started = Date.now();
  const result = spawn(exe, args, {
    shell: false,
    windowsHide: true,
    encoding: 'utf8',
    timeout: timeoutMs,
    maxBuffer: MAX_OUTPUT,
    env: process.env,
  });
  const elapsedMs = Date.now() - started;
  if (result && result.error) {
    return {
      ok: false,
      status: result.error.code === 'ETIMEDOUT' ? 'timeout' : 'error',
      code: result.error.code || 'PROCESS_ERROR',
      elapsedMs,
      stdout: boundedText(result.stdout),
      stderr: boundedText(result.stderr),
    };
  }
  return {
    ok: true,
    status: 'complete',
    exitCode: Number.isInteger(result && result.status) ? result.status : null,
    signal: result && result.signal || null,
    elapsedMs,
    stdout: boundedText(result && result.stdout, MAX_OUTPUT),
    stderr: boundedText(result && result.stderr, MAX_OUTPUT),
  };
}
function collectFlossStrings(value, out, depth = 0) {
  if (depth > 8 || out.length >= 5000 || value == null) return;
  if (typeof value === 'string') return;
  if (Array.isArray(value)) {
    for (const item of value) collectFlossStrings(item, out, depth + 1);
    return;
  }
  if (typeof value === 'object') {
    if (typeof value.string === 'string') out.push(value.string.slice(0, 2048));
    for (const item of Object.values(value)) collectFlossStrings(item, out, depth + 1);
  }
}

class MultiEngineScanner {
  constructor(options = {}) {
    this.binaryRoot = options.binaryRoot || DEFAULT_BIN;
    this.rulesPath = options.rulesPath || DEFAULT_RULES;
    this.platform = options.platform || process.platform;
    this.spawn = options.spawnSync || spawnSync;
    this.defenderPath = options.defenderPath || null;
  }

  _path(name) { return path.join(this.binaryRoot, name); }

  _bundleMarker() {
    const markerPath = this._path(BUNDLE_MARKER);
    if (!fs.existsSync(markerPath)) return null;
    try { return JSON.parse(fs.readFileSync(markerPath, 'utf8')); } catch (_) { return null; }
  }

  _findDefender() {
    if (this.platform !== 'win32') return null;
    if (this.defenderPath && fs.existsSync(this.defenderPath)) return this.defenderPath;

    const programData = process.env.ProgramData || 'C:\\ProgramData';
    const platformRoot = path.join(programData, 'Microsoft', 'Windows Defender', 'Platform');
    try {
      const dirs = fs.readdirSync(platformRoot, { withFileTypes: true })
        .filter(entry => entry.isDirectory())
        .map(entry => entry.name)
        .sort((a, b) => b.localeCompare(a, undefined, { numeric: true }));
      for (const dir of dirs) {
        const candidate = path.join(platformRoot, dir, 'MpCmdRun.exe');
        if (fs.existsSync(candidate)) return candidate;
      }
    } catch (_) {}

    const programFiles = process.env.ProgramFiles || 'C:\\Program Files';
    const fallback = path.join(programFiles, 'Windows Defender', 'MpCmdRun.exe');
    return fs.existsSync(fallback) ? fallback : null;
  }

  capabilities() {
    const marker = this._bundleMarker();
    const defender = this._findDefender();
    return {
      schemaVersion: '2.0',
      bundleExpected: !!marker,
      bundle: marker,
      engines: {
        yaraX: { available: fs.existsSync(this._path('yr.exe')), executable: 'yr.exe' },
        capa: { available: fs.existsSync(this._path('capa.exe')), executable: 'capa.exe' },
        floss: { available: fs.existsSync(this._path('floss.exe')), executable: 'floss.exe' },
        defender: { available: !!defender, executable: defender ? path.basename(defender) : null },
      },
    };
  }

  scanBuffer(name, bytes, options = {}) {
    const input = Buffer.from(bytes || []);
    if (!input.length) {
      return { schemaVersion: '2.0', verdict: 'inconclusive', code: 'MULTI_ENGINE_EMPTY_FILE', engines: {}, coverage: { complete: false, requiredForSafe: false } };
    }
    if (input.length > MAX_FILE_SIZE) {
      return { schemaVersion: '2.0', verdict: 'inconclusive', code: 'MULTI_ENGINE_TOO_LARGE', engines: {}, coverage: { complete: false, requiredForSafe: false } };
    }
    const rawExt = path.extname(String(name || '')).toLowerCase();
    const ext = SUPPORTED_EXTENSIONS.has(rawExt) ? rawExt : '.bin';
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'malguard-multi-'));
    const sample = path.join(dir, 'sample' + ext);
    try {
      fs.writeFileSync(sample, input, { mode: 0o600 });
      return this.scanPath(sample, { ...options, extension: ext });
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }

  scanPath(filePath, options = {}) {
    const ext = options.extension || path.extname(filePath).toLowerCase();
    const pe = PE_EXTENSIONS.has(ext);
    const capabilities = this.capabilities();
    const engines = {
      yaraX: this._scanYara(filePath, capabilities.engines.yaraX.available),
      capa: pe ? this._scanCapa(filePath, capabilities.engines.capa.available) : { status: 'not_applicable', verdict: 'inconclusive', reason: 'non_pe_input' },
      floss: pe ? this._scanFloss(filePath, capabilities.engines.floss.available) : { status: 'not_applicable', verdict: 'inconclusive', reason: 'non_pe_input' },
      defender: this._scanDefender(filePath, capabilities.engines.defender.available),
    };

    const required = pe ? ['yaraX', 'capa', 'floss'] : ['yaraX'];
    const requiredForSafe = capabilities.bundleExpected === true;
    const complete = required.every(name => engines[name] && engines[name].status === 'complete');
    const suspicious = Object.values(engines).filter(e => e && e.verdict === 'suspicious').length;
    const malicious = Object.values(engines).filter(e => e && e.verdict === 'malicious').length;

    let verdict = 'inconclusive';
    if (malicious > 0) verdict = 'malicious';
    else if (suspicious > 0) verdict = 'suspicious';
    else if (complete) verdict = 'safe';

    return {
      schemaVersion: '2.0',
      engineSet: 'MalGuard Multi-Engine',
      mode: options.mode || 'pro',
      verdict,
      riskScore: verdict === 'malicious' ? 100 : verdict === 'suspicious' ? Math.min(90, 60 + suspicious * 10) : verdict === 'safe' ? 8 : 45,
      engines,
      coverage: {
        required,
        requiredForSafe,
        complete,
        completed: Object.values(engines).filter(e => e && e.status === 'complete').length,
        unavailable: Object.values(engines).filter(e => e && ['unavailable', 'error', 'timeout'].includes(e.status)).length,
      },
      policy: {
        executesSample: false,
        defenderRemediationDisabled: true,
        rawEngineOutputReturned: false,
      },
    };
  }

  _scanYara(filePath, available) {
    if (!available || !fs.existsSync(this.rulesPath)) return { status: 'unavailable', verdict: 'inconclusive', matches: [] };
    const run = runTool(this.spawn, this._path('yr.exe'), ['scan', '--output-format=ndjson', '-m', '-g', this.rulesPath, filePath], 30000);
    if (!run.ok) return { status: run.status, verdict: 'inconclusive', code: run.code || 'YARAX_PROCESS_FAILED', elapsedMs: run.elapsedMs, matches: [] };
    if (![0, 1].includes(run.exitCode)) return { status: 'error', verdict: 'inconclusive', code: 'YARAX_EXIT_' + run.exitCode, elapsedMs: run.elapsedMs, matches: [] };

    const rules = [];
    for (const line of String(run.stdout || '').split(/\r?\n/)) {
      if (!line.trim()) continue;
      const doc = safeJson(line);
      if (!doc || !Array.isArray(doc.rules)) continue;
      for (const rule of doc.rules) {
        const id = String(rule && rule.identifier || '').slice(0, 160);
        if (!id) continue;
        const severity = id.startsWith('MG_HIGH_') ? 'high' : id.startsWith('MG_MEDIUM_') ? 'medium' : 'info';
        rules.push({ id, severity });
      }
    }

    const high = rules.filter(r => r.severity === 'high').length;
    const medium = rules.filter(r => r.severity === 'medium').length;
    return {
      status: 'complete',
      verdict: high > 0 || medium >= 2 ? 'suspicious' : 'safe',
      elapsedMs: run.elapsedMs,
      matchCount: rules.length,
      highCount: high,
      mediumCount: medium,
      matches: rules.slice(0, 50),
    };
  }

  _scanCapa(filePath, available) {
    if (!available) return { status: 'unavailable', verdict: 'inconclusive', capabilityCount: 0, highRiskCount: 0 };
    const run = runTool(this.spawn, this._path('capa.exe'), ['-j', filePath], 120000);
    if (!run.ok) return { status: run.status, verdict: 'inconclusive', code: run.code || 'CAPA_PROCESS_FAILED', elapsedMs: run.elapsedMs, capabilityCount: 0, highRiskCount: 0 };

    const doc = safeJson(run.stdout);
    if (!doc) {
      const unsupported = /unsupported|format|not a pe|not a supported/i.test(run.stderr || '');
      return { status: unsupported ? 'not_applicable' : 'error', verdict: 'inconclusive', code: unsupported ? 'CAPA_UNSUPPORTED' : 'CAPA_JSON_INVALID', elapsedMs: run.elapsedMs, capabilityCount: 0, highRiskCount: 0 };
    }

    const rules = doc.rules && typeof doc.rules === 'object' ? doc.rules : {};
    const names = Object.keys(rules);
    const highRisk = names.filter(name => {
      const text = (name + ' ' + JSON.stringify(rules[name] || {})).toLowerCase();
      return /credential|keylog|process injection|inject code|c2\/|command shell|persistence\/service|exfil|disable security|ransom|encrypt files/.test(text);
    });

    return {
      status: 'complete',
      verdict: highRisk.length >= 2 ? 'suspicious' : 'safe',
      elapsedMs: run.elapsedMs,
      capabilityCount: names.length,
      highRiskCount: highRisk.length,
      highRiskCapabilities: highRisk.slice(0, 40),
    };
  }

  _scanFloss(filePath, available) {
    if (!available) return { status: 'unavailable', verdict: 'inconclusive', extractedStringCount: 0, indicatorCategories: [] };
    const run = runTool(this.spawn, this._path('floss.exe'), [filePath, '-j'], 150000);
    if (!run.ok) return { status: run.status, verdict: 'inconclusive', code: run.code || 'FLOSS_PROCESS_FAILED', elapsedMs: run.elapsedMs, extractedStringCount: 0, indicatorCategories: [] };

    const doc = safeJson(run.stdout);
    if (!doc) return { status: 'error', verdict: 'inconclusive', code: 'FLOSS_JSON_INVALID', elapsedMs: run.elapsedMs, extractedStringCount: 0, indicatorCategories: [] };

    const values = [];
    collectFlossStrings(doc.strings || {}, values);
    const categories = new Set();
    for (const value of values) {
      const s = String(value).toLowerCase();
      if (/login data|local state|web data|cookies/.test(s)) categories.add('credential_targets');
      if (/powershell|cmd\.exe|wscript|cscript/.test(s)) categories.add('command_execution');
      if (/http:\/\/|https:\/\/|websocket|winhttp|internetopen/.test(s)) categories.add('networking');
      if (/createremotethread|writeprocessmemory|virtualallocex/.test(s)) categories.add('process_injection');
      if (/set-mppreference|disablerealtimemonitoring|disablebehaviormonitoring/.test(s)) categories.add('security_tampering');
    }
    const indicatorCategories = [...categories];

    return {
      status: 'complete',
      verdict: indicatorCategories.length >= 2 ? 'suspicious' : 'safe',
      elapsedMs: run.elapsedMs,
      extractedStringCount: values.length,
      indicatorCategories,
      rawStringsExposed: false,
    };
  }

  _scanDefender(filePath, available) {
    const exe = this._findDefender();
    if (!available || !exe) return { status: 'unavailable', verdict: 'inconclusive', remediationDisabled: true };

    const run = runTool(this.spawn, exe, ['-Scan', '-ScanType', '3', '-File', filePath, '-DisableRemediation'], 120000);
    if (!run.ok) return { status: run.status, verdict: 'inconclusive', code: run.code || 'DEFENDER_PROCESS_FAILED', elapsedMs: run.elapsedMs, remediationDisabled: true };

    const combined = String(run.stdout || '') + '\n' + String(run.stderr || '');
    const detection = /(?:Threat\s*[:=]|Trojan:|Virus:|Backdoor:|Ransom:|HackTool:|Behavior:)/i.test(combined);

    if (run.exitCode === 0) return { status: 'complete', verdict: 'safe', elapsedMs: run.elapsedMs, detected: false, remediationDisabled: true };
    if (run.exitCode === 2 && detection) return { status: 'complete', verdict: 'malicious', elapsedMs: run.elapsedMs, detected: true, remediationDisabled: true };
    return { status: 'complete', verdict: 'inconclusive', elapsedMs: run.elapsedMs, detected: false, code: 'DEFENDER_EXIT_' + run.exitCode, remediationDisabled: true };
  }
}

module.exports = { MultiEngineScanner, PE_EXTENSIONS, SUPPORTED_EXTENSIONS };
