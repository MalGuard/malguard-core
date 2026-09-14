'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { URL } = require('url');
const { ScannerBridge } = require('./scanner-bridge.js');
const { WindowsUserSpaceGuardAgent } = require('../desktop-guard/windows-agent/agent.js');
const { ManagedInstallGuard } = require('../desktop-guard/windows-agent/managed-install.js');
const { SandboxController } = require('./sandbox/sandbox-controller.js');
const { IncidentStore } = require('../desktop-guard/windows-agent/incident-store.js');
const { SettingsStore } = require('./settings-store.js');
const { ProtectedFolderAclGate } = require('../desktop-guard/windows-agent/acl-protection.js');
const { ThreatIntelService } = require('./threat-intel/service.js');
const { ModelScanPipelineManager } = require('./pro-scan-pipeline.js');
const { EntitlementGate } = require('./entitlement/entitlement-gate.js');

const ROOT = path.resolve(__dirname, '..');
const PUBLIC = path.join(__dirname, 'public');
const PORT = Number(process.env.MALGUARD_PORT || 18777);
const HOST = '127.0.0.1';
const threatIntel = new ThreatIntelService();
const scanner = new ScannerBridge({ threatIntel });
const sandbox = new SandboxController({ allowExperimentalDetonation: process.env.MALGUARD_EXPERIMENTAL_SANDBOX === '1' });
const modelPipeline = new ModelScanPipelineManager({ scanner, sandbox });
const entitlementGate = new EntitlementGate();

function json(res, status, body) {
  const data = Buffer.from(JSON.stringify(body, null, 2));
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': data.length,
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  });
  res.end(data);
}

async function readJson(req, max = 128 * 1024) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > max) throw Object.assign(new Error('request too large'), { code: 'REQUEST_TOO_LARGE' });
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

function contentType(file) {
  const ext = path.extname(file).toLowerCase();
  if (ext === '.html') return 'text/html; charset=utf-8';
  if (ext === '.js') return 'application/javascript; charset=utf-8';
  if (ext === '.css') return 'text/css; charset=utf-8';
  return 'application/octet-stream';
}

async function serveStatic(urlPath, res) {
  const requested = urlPath === '/' ? '/index.html' : urlPath;
  const target = path.resolve(PUBLIC, '.' + requested);
  if (!(target === PUBLIC || target.startsWith(PUBLIC + path.sep))) return false;
  try {
    const stat = await fs.promises.stat(target);
    if (!stat.isFile()) return false;
    const data = await fs.promises.readFile(target);
    res.writeHead(200, { 'content-type': contentType(target), 'content-length': data.length, 'cache-control': 'no-store' });
    res.end(data);
    return true;
  } catch (_) { return false; }
}

const settingsStore = new SettingsStore(process.env.MALGUARD_SETTINGS_FILE || null);

function safeConfig() {
  const persisted = settingsStore.loadSync();
  const envWatch = process.env.MALGUARD_WATCH_ROOT ? [path.resolve(process.env.MALGUARD_WATCH_ROOT)] : persisted.watchRoots;
  return settingsStore.validate({
    watchRoots: envWatch,
    quarantineRoot: path.resolve(process.env.MALGUARD_QUARANTINE_ROOT || persisted.quarantineRoot),
    stagingRoot: path.resolve(process.env.MALGUARD_STAGING_ROOT || persisted.stagingRoot),
  });
}

let config = safeConfig();
let incidentStore = new IncidentStore(config.quarantineRoot);
let agent = null;
let managedInstall = null;
let aclGate = null;

async function applySettings(nextSettings) {
  const validated = settingsStore.validate(nextSettings);
  if (agent && agent.watcher && agent.watcher.active) await agent.stopWatching();
  agent = null;
  managedInstall = null;
  aclGate = null;
  const saved = await settingsStore.save(validated);
  config = saved;
  incidentStore = new IncidentStore(config.quarantineRoot);
  return saved;
}

function normalizeVerdict(result) {
  const v = result && result.finalVerdict;
  if (v === 'safe' || v === 'suspicious' || v === 'malicious' || v === 'inconclusive') return v;
  return 'inconclusive';
}

function entitlementDenied(res, error) {
  return json(res, 403, {
    ok: false,
    code: error.code || 'ENTITLEMENT_REQUIRED',
    message: error.message,
    requiredPlan: error.requiredPlan || null,
    currentPlan: error.currentPlan || 'standard',
  });
}

function ensureAgent() {
  if (agent) return agent;
  if (!config.watchRoots.length) {
    const error = new Error('No watch root configured. Set MALGUARD_WATCH_ROOT.');
    error.code = 'WATCH_ROOT_NOT_CONFIGURED';
    throw error;
  }
  agent = new WindowsUserSpaceGuardAgent({
    roots: config.watchRoots,
    quarantineRoot: config.quarantineRoot,
    scanner: async filePath => {
      const result = await scanner.scanPath(filePath, 'pro');
      return {
        verdict: normalizeVerdict(result).toUpperCase(),
        reasons: [result.note || result.hardeningError || 'MalGuard desktop scan'],
        raw: result,
      };
    },
    onIncident: async report => {
      await incidentStore.append(report);
    },
  });
  aclGate = new ProtectedFolderAclGate({ roots: config.watchRoots, stateRoot: config.quarantineRoot });
  managedInstall = new ManagedInstallGuard({
    gameRoots: config.watchRoots,
    stagingRoot: config.stagingRoot,
    quarantineStore: agent.store,
    scanner: async filePath => {
      const result = await scanner.scanPath(filePath, 'pro');
      return {
        verdict: normalizeVerdict(result).toUpperCase(),
        reasons: [result.note || result.hardeningError || 'MalGuard managed install scan'],
        raw: result,
      };
    },
  });
  return agent;
}

async function handler(req, res) {
  const url = new URL(req.url, `http://${HOST}:${PORT}`);
  try {
    if (req.method === 'GET' && url.pathname === '/api/status') {
      return json(res, 200, {
        ok: true,
        product: 'MalGuard Desktop',
        version: '0.6.0-dev',
        supportedModels: ['standard', 'plus', 'pro'],
        entitlement: entitlementGate.status(),
        scanner: 'hardened-core-bridge',
        guardConfigured: config.watchRoots.length > 0,
        watching: !!(agent && agent.watcher && agent.watcher.active),
        guardHealth: agent ? agent.getHealth() : { state: 'stopped' },
        watchRoots: config.watchRoots,
        quarantineRoot: config.quarantineRoot,
        sandboxMode: process.env.MALGUARD_EXPERIMENTAL_SANDBOX === '1' ? 'windows-sandbox-experimental' : 'fail-closed-acceptance-pending',
        threatIntel: await threatIntel.status(),
      });
    }

    if (req.method === 'GET' && url.pathname === '/api/entitlement/status') {
      return json(res, 200, { ok: true, entitlement: entitlementGate.status() });
    }

    if (req.method === 'GET' && url.pathname === '/api/threat-intel/status') {
      return json(res, 200, { ok: true, status: await threatIntel.status() });
    }
    if (req.method === 'POST' && url.pathname === '/api/threat-intel/credential') {
      const body = await readJson(req, 16 * 1024);
      if (typeof body.authKey !== 'string') return json(res, 400, { ok: false, code: 'AUTH_KEY_REQUIRED' });
      const stored = await threatIntel.credentials.setAuthKey(body.authKey);
      return json(res, 200, { ok: true, storage: stored.storage });
    }
    if (req.method === 'DELETE' && url.pathname === '/api/threat-intel/credential') {
      const cleared = await threatIntel.credentials.clear();
      return json(res, 200, cleared);
    }

    if (req.method === 'GET' && url.pathname === '/api/settings') {
      return json(res, 200, { ok: true, settings: config });
    }
    if (req.method === 'POST' && url.pathname === '/api/settings') {
      const body = await readJson(req);
      const settings = await applySettings(body);
      return json(res, 200, { ok: true, settings, guardRestarted: false });
    }

    if (req.method === 'POST' && url.pathname === '/api/scan-path') {
      const body = await readJson(req);
      if (typeof body.path !== 'string') return json(res, 400, { ok: false, code: 'PATH_REQUIRED' });
      const result = await scanner.scanPath(body.path, body.mode === 'free' ? 'free' : 'pro');
      return json(res, 200, { ok: true, result });
    }

    if (req.method === 'POST' && url.pathname === '/api/model-scan/start') {
      const body = await readJson(req);
      if (typeof body.path !== 'string' || !body.path.trim()) return json(res, 400, { ok: false, code: 'PATH_REQUIRED' });
      try {
        const model = body.model || 'standard';
        const entitlement = entitlementGate.requireModel(model);
        const session = modelPipeline.start(body.path, model);
        return json(res, 202, { ok: true, entitlement: { plan: entitlement.plan, source: entitlement.source }, session });
      } catch (error) {
        if (error.code === 'INVALID_MODEL') return json(res, 400, { ok: false, code: error.code, message: error.message });
        if (error.code && error.code.startsWith('ENTITLEMENT_')) return entitlementDenied(res, error);
        throw error;
      }
    }
    if (req.method === 'GET' && url.pathname === '/api/model-scan/status') {
      const id = url.searchParams.get('id');
      if (!id) return json(res, 400, { ok: false, code: 'SCAN_ID_REQUIRED' });
      const session = modelPipeline.snapshot(id);
      if (!session) return json(res, 404, { ok: false, code: 'MODEL_SCAN_NOT_FOUND' });
      return json(res, 200, { ok: true, session });
    }

    if (req.method === 'POST' && url.pathname === '/api/pro-scan/start') {
      const body = await readJson(req);
      if (typeof body.path !== 'string' || !body.path.trim()) return json(res, 400, { ok: false, code: 'PATH_REQUIRED' });
      try {
        const entitlement = entitlementGate.requireModel('plus');
        const session = modelPipeline.start(body.path, 'plus');
        return json(res, 202, { ok: true, deprecated: true, mappedModel: 'plus', entitlement: { plan: entitlement.plan, source: entitlement.source }, session });
      } catch (error) {
        if (error.code && error.code.startsWith('ENTITLEMENT_')) return entitlementDenied(res, error);
        throw error;
      }
    }
    if (req.method === 'GET' && url.pathname === '/api/pro-scan/status') {
      const id = url.searchParams.get('id');
      if (!id) return json(res, 400, { ok: false, code: 'SCAN_ID_REQUIRED' });
      const session = modelPipeline.snapshot(id);
      if (!session) return json(res, 404, { ok: false, code: 'PRO_SCAN_NOT_FOUND' });
      return json(res, 200, { ok: true, deprecated: true, mappedModel: 'plus', session });
    }

    if (req.method === 'GET' && url.pathname === '/api/access-gate/status') {
      ensureAgent();
      return json(res, 200, await aclGate.status());
    }
    if (req.method === 'POST' && url.pathname === '/api/access-gate/enable') {
      ensureAgent();
      const result = await aclGate.protectAll();
      return json(res, result.ok ? 200 : 409, result);
    }
    if (req.method === 'POST' && url.pathname === '/api/access-gate/disable') {
      ensureAgent();
      return json(res, 200, await aclGate.restoreAll());
    }

    if (req.method === 'POST' && url.pathname === '/api/guard/start') {
      const a = ensureAgent();
      return json(res, 200, await a.startWatching());
    }
    if (req.method === 'POST' && url.pathname === '/api/guard/stop') {
      if (!agent) return json(res, 200, { ok: true, active: false });
      return json(res, 200, await agent.stopWatching());
    }
    if (req.method === 'GET' && url.pathname === '/api/quarantine') {
      const a = ensureAgent();
      return json(res, 200, { ok: true, entries: await a.listQuarantine() });
    }
    if (req.method === 'POST' && url.pathname === '/api/quarantine/restore') {
      const body = await readJson(req);
      if (typeof body.id !== 'string') return json(res, 400, { ok: false, code: 'ID_REQUIRED' });
      const a = ensureAgent();
      return json(res, 200, { ok: true, entry: await a.restore(body.id) });
    }
    if (req.method === 'POST' && url.pathname === '/api/install') {
      const body = await readJson(req);
      if (typeof body.source !== 'string' || typeof body.destination !== 'string') {
        return json(res, 400, { ok: false, code: 'SOURCE_AND_DESTINATION_REQUIRED' });
      }
      ensureAgent();
      return json(res, 200, await managedInstall.install(body.source, body.destination));
    }
    if (req.method === 'GET' && url.pathname === '/api/incidents') {
      return json(res, 200, { ok: true, incidents: await incidentStore.list(100) });
    }
    if (req.method === 'POST' && url.pathname === '/api/sandbox/self-test') {
      return json(res, 200, await sandbox.selfTest());
    }
    if (req.method === 'POST' && url.pathname === '/api/sandbox/analyze') {
      const body = await readJson(req);
      const result = await sandbox.analyzeUntrustedSample(body.path);
      return json(res, result.ok ? 200 : 409, result);
    }
    if (req.method === 'POST' && url.pathname === '/api/self-test') {
      const probe = await sandbox.selfTest();
      const fixture = path.join(ROOT, 'tests', 'corpus', 'benign-config-read.lua');
      const scan = await scanner.scanPath(fixture, 'pro');
      return json(res, 200, {
        ok: probe.ok && scan.finalVerdict === 'safe',
        checks: {
          scanner: { ok: scan.finalVerdict === 'safe', verdict: scan.finalVerdict },
          sandboxIsolationProbe: probe,
          guardConfiguration: { ok: config.watchRoots.length > 0, configured: config.watchRoots.length > 0 },
        },
      });
    }

    if (req.method === 'GET' && await serveStatic(url.pathname, res)) return;
    json(res, 404, { ok: false, code: 'NOT_FOUND' });
  } catch (error) {
    json(res, 500, { ok: false, code: error.code || 'INTERNAL_ERROR', message: error.message || 'internal error' });
  }
}

function startServer(port = PORT) {
  const server = http.createServer(handler);
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, HOST, () => resolve(server));
  });
}

if (require.main === module) {
  startServer().then(async () => {
    if (process.env.MALGUARD_SERVICE_MODE === '1') {
      if (!config.watchRoots.length) {
        const error = new Error('Windows service mode requires a configured protected game root.');
        error.code = 'SERVICE_WATCH_ROOT_NOT_CONFIGURED';
        throw error;
      }
      const a = ensureAgent();
      const gate = await aclGate.protectAll();
      if (!gate || gate.ok !== true) {
        const error = new Error('Protected-folder access gate failed during service startup.');
        error.code = 'SERVICE_ACCESS_GATE_START_FAILED';
        throw error;
      }
      const result = await a.startWatching();
      if (!result || result.ok !== true || !result.health || result.health.state !== 'healthy') {
        const error = new Error('Real-time guard failed to reach healthy state during service startup.');
        error.code = 'SERVICE_GUARD_START_FAILED';
        throw error;
      }
    }
    console.log(`MalGuard Desktop 0.6.0-dev running at http://${HOST}:${PORT}`);
    console.log('Localhost only. No remote binding.');
  }).catch(error => {
    console.error(error.stack || error);
    process.exit(1);
  });
}

module.exports = { startServer, handler, scanner, sandbox, modelPipeline, proPipeline: modelPipeline, entitlementGate, settingsStore, applySettings, getConfig: () => ({ ...config, watchRoots: [...config.watchRoots] }) };
