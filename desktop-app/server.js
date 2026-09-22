'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { URL } = require('url');
const { ScannerBridge } = require('./scanner-bridge.js');
const { WindowsUserSpaceGuardAgent } = require('../desktop-guard/windows-agent/agent.js');
const { ManagedInstallGuard } = require('../desktop-guard/windows-agent/managed-install.js');
const { ProtectionCoordinator } = require('../desktop-guard/windows-agent/protection-coordinator.js');
const { RuntimeGameProcessGuard } = require('../desktop-guard/windows-agent/runtime-process-guard.js');
const { SandboxController } = require('./sandbox/sandbox-controller.js');
const { IsolationBackendRouter } = require('./sandbox/isolation-backend-router.js');
const { EmbeddedValidationLab } = require('./sandbox/embedded-validation-lab.js');
const { IncidentStore } = require('../desktop-guard/windows-agent/incident-store.js');
const { SettingsStore } = require('./settings-store.js');
const { recordFirstSuccessfulLaunch } = require('./metrics/first-launch-counter.js');
const { sendCompatibilityInstallReport } = require('./metrics/compatibility-install-report.js');
const { ProtectedFolderAclGate } = require('../desktop-guard/windows-agent/acl-protection.js');
const { ThreatIntelService } = require('./threat-intel/service.js');
const { ModelScanPipelineManager } = require('./pro-scan-pipeline.js');
const { EntitlementGate } = require('./entitlement/entitlement-gate.js');
const { LocalErrorReporter, safeText } = require('./diagnostics/error-reporter.js');

const ROOT = path.resolve(__dirname, '..');
const PUBLIC = path.join(__dirname, 'public');
const DESKTOP_VERSION = fs.readFileSync(path.join(ROOT, 'DESKTOP-VERSION'), 'utf8').trim();
const PORT = Number(process.env.MALGUARD_PORT || 18777);
const HOST = '127.0.0.1';
const threatIntel = new ThreatIntelService();
const scanner = new ScannerBridge({ threatIntel });
const isolationBackend = new IsolationBackendRouter({ prefer: 'windows-sandbox' });
const sandbox = new SandboxController({
  isolationBackend,
  autoCertify: true,
});
const validationLab = new EmbeddedValidationLab({ windowsBackend: sandbox.windowsBackend });
const modelPipeline = new ModelScanPipelineManager({ scanner, sandbox });
const entitlementGate = new EntitlementGate();
const errorReporter = new LocalErrorReporter();

function json(res, status, body) {
  const data = Buffer.from(JSON.stringify(body, null, 2));
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': data.length, 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
  res.end(data);
}

async function readJson(req, max = 128 * 1024) {
  const chunks = []; let size = 0;
  for await (const chunk of req) { size += chunk.length; if (size > max) throw Object.assign(new Error('request too large'), { code: 'REQUEST_TOO_LARGE' }); chunks.push(chunk); }
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
  const requested = urlPath === '/' ? '/index.html' : urlPath; const target = path.resolve(PUBLIC, '.' + requested);
  if (!(target === PUBLIC || target.startsWith(PUBLIC + path.sep))) return false;
  try { const stat = await fs.promises.stat(target); if (!stat.isFile()) return false; const data = await fs.promises.readFile(target); res.writeHead(200, { 'content-type': contentType(target), 'content-length': data.length, 'cache-control': 'no-store' }); res.end(data); return true; } catch (_) { return false; }
}

const settingsStore = new SettingsStore(process.env.MALGUARD_SETTINGS_FILE || null);
function safeConfig() {
  const persisted = settingsStore.loadSync(); const envWatch = process.env.MALGUARD_WATCH_ROOT ? [path.resolve(process.env.MALGUARD_WATCH_ROOT)] : persisted.watchRoots;
  return settingsStore.validate({ watchRoots: envWatch, quarantineRoot: path.resolve(process.env.MALGUARD_QUARANTINE_ROOT || persisted.quarantineRoot), stagingRoot: path.resolve(process.env.MALGUARD_STAGING_ROOT || persisted.stagingRoot) });
}
let config = safeConfig(); let incidentStore = new IncidentStore(config.quarantineRoot); let agent = null; let managedInstall = null; let aclGate = null; let runtimeProcessGuard = null; let protectionCoordinator = null;

async function applySettings(nextSettings) {
  const validated = settingsStore.validate(nextSettings);
  if (protectionCoordinator) {
    const protection = protectionCoordinator.getCachedStatus();
    if (protection.active || protection.accessGateProtected) {
      const stopped = await protectionCoordinator.stop();
      if (!stopped.ok) { const error = new Error('Real-time protection could not be stopped safely before settings change.'); error.code = 'REALTIME_PROTECTION_STOP_FAILED'; throw error; }
    }
  } else if (agent && agent.watcher && agent.watcher.active) {
    await agent.stopWatching();
  }
  agent = null; managedInstall = null; aclGate = null; runtimeProcessGuard = null; protectionCoordinator = null;
  const saved = await settingsStore.save(validated); config = saved; incidentStore = new IncidentStore(config.quarantineRoot); return saved;
}
function normalizeVerdict(result) { const v = result && result.finalVerdict; return ['safe', 'suspicious', 'malicious', 'inconclusive'].includes(v) ? v : 'inconclusive'; }
function entitlementDenied(res, error) { return json(res, 403, { ok: false, code: error.code || 'ENTITLEMENT_REQUIRED', message: error.message, requiredPlan: error.requiredPlan || null, currentPlan: error.currentPlan || 'standard' }); }
function requirePlanForApi(res, plan) { try { return entitlementGate.requirePlan(plan); } catch (error) { if (error.code && error.code.startsWith('ENTITLEMENT_')) { entitlementDenied(res, error); return null; } throw error; } }

async function recordRuntimeError(error, context) {
  try { return await errorReporter.record(error, context); } catch (_) { return null; }
}

function ensureAgent() {
  if (agent) return agent;
  if (!config.watchRoots.length) { const error = new Error('No watch root configured. Set MALGUARD_WATCH_ROOT.'); error.code = 'WATCH_ROOT_NOT_CONFIGURED'; throw error; }
  const serviceMode = process.env.MALGUARD_SERVICE_MODE === '1';
  agent = new WindowsUserSpaceGuardAgent({ roots: config.watchRoots, quarantineRoot: config.quarantineRoot, scanner: async filePath => { const result = await scanner.scanPath(filePath, 'pro'); return { verdict: normalizeVerdict(result).toUpperCase(), reasons: [result.note || result.hardeningError || 'MalGuard desktop scan'], raw: result }; }, onIncident: async report => { await incidentStore.append(report); } });
  aclGate = new ProtectedFolderAclGate({ roots: config.watchRoots, stateRoot: config.quarantineRoot });
  runtimeProcessGuard = new RuntimeGameProcessGuard({
    roots: config.watchRoots,
    serviceMode,
    platform: process.platform,
    trustedPath: filePath => agent.isTrustedPath(filePath),
    scanner: async filePath => {
      const result = await scanner.scanPath(filePath, 'pro');
      return { verdict: normalizeVerdict(result).toUpperCase(), reasons: [result.note || result.hardeningError || 'MalGuard runtime module scan'], raw: result };
    },
    onIncident: async report => { await incidentStore.append(report); },
  });
  protectionCoordinator = new ProtectionCoordinator({ agent, accessGate: aclGate, runtimeGuard: runtimeProcessGuard, requireRuntimeProcessProtection: true, serviceMode, platform: process.platform });
  managedInstall = new ManagedInstallGuard({ gameRoots: config.watchRoots, stagingRoot: config.stagingRoot, quarantineStore: agent.store, scanner: async filePath => { const result = await scanner.scanPath(filePath, 'pro'); return { verdict: normalizeVerdict(result).toUpperCase(), reasons: [result.note || result.hardeningError || 'MalGuard managed install scan'], raw: result }; } });
  return agent;
}

async function handler(req, res) {
  const url = new URL(req.url, `http://${HOST}:${PORT}`);
  try {
    if (req.method === 'GET' && url.pathname === '/api/status') {
      const protection = protectionCoordinator ? protectionCoordinator.getCachedStatus() : { ok:false, active:false, completeProtection:false, accessGateProtected:false, watcherHealthy:false, runtimeProcessHealthy:false, runtimeProcessProtection:null, state:'stopped', reason:null };
      const sandboxCertification = sandbox.certificationStatus();
      const sandboxMode = sandboxCertification.ok === true
        ? `${sandboxCertification.selectedBackend || 'isolation-backend'}-certified`
        : sandboxCertification.state === 'running'
          ? 'isolation-backend-self-certifying'
          : 'fail-closed-until-isolation-backend-certified';
      return json(res, 200, { ok: true, product: 'MalGuard Desktop', version: DESKTOP_VERSION, supportedModels: ['standard', 'plus', 'pro'], entitlement: entitlementGate.status(), scanner: 'hardened-core-bridge', guardConfigured: config.watchRoots.length > 0, watching: protection.completeProtection === true, realtimeProtection: protection, runtimeProcessProtection: protection.runtimeProcessProtection, guardHealth: agent ? agent.getHealth() : { state: 'stopped' }, watchRoots: config.watchRoots, quarantineRoot: config.quarantineRoot, sandboxMode, sandboxCertification, threatIntel: await threatIntel.status() });
    }
    if (req.method === 'GET' && url.pathname === '/api/entitlement/status') return json(res, 200, { ok: true, entitlement: entitlementGate.status() });
    if (req.method === 'GET' && url.pathname === '/api/threat-intel/status') return json(res, 200, { ok: true, status: await threatIntel.status() });
    if (req.method === 'POST' && url.pathname === '/api/threat-intel/credential') { const body = await readJson(req, 16 * 1024); if (typeof body.authKey !== 'string') return json(res, 400, { ok: false, code: 'AUTH_KEY_REQUIRED' }); const stored = await threatIntel.credentials.setAuthKey(body.authKey); return json(res, 200, { ok: true, storage: stored.storage }); }
    if (req.method === 'DELETE' && url.pathname === '/api/threat-intel/credential') return json(res, 200, await threatIntel.credentials.clear());
    if (req.method === 'GET' && url.pathname === '/api/settings') return json(res, 200, { ok: true, settings: config });
    if (req.method === 'POST' && url.pathname === '/api/settings') { const body = await readJson(req); const settings = await applySettings(body); return json(res, 200, { ok: true, settings, guardRestarted: false }); }
    if (req.method === 'POST' && url.pathname === '/api/scan-path') { const body = await readJson(req); if (typeof body.path !== 'string') return json(res, 400, { ok: false, code: 'PATH_REQUIRED' }); const requestedMode = body.mode === 'free' ? 'free' : 'pro'; if (requestedMode === 'pro') { const entitlement = requirePlanForApi(res, 'plus'); if (!entitlement) return; } const result = await scanner.scanPath(body.path, requestedMode); return json(res, 200, { ok: true, result }); }
    if (req.method === 'POST' && url.pathname === '/api/model-scan/start') { const body = await readJson(req); if (typeof body.path !== 'string' || !body.path.trim()) return json(res, 400, { ok: false, code: 'PATH_REQUIRED' }); try { const model = body.model || 'standard'; const entitlement = entitlementGate.requireModel(model); const session = modelPipeline.start(body.path, model); return json(res, 202, { ok: true, entitlement: { plan: entitlement.plan, source: entitlement.source }, session }); } catch (error) { if (error.code === 'INVALID_MODEL') return json(res, 400, { ok: false, code: error.code, message: error.message }); if (error.code && error.code.startsWith('ENTITLEMENT_')) return entitlementDenied(res, error); throw error; } }
    if (req.method === 'GET' && url.pathname === '/api/model-scan/status') { const id = url.searchParams.get('id'); if (!id) return json(res, 400, { ok: false, code: 'SCAN_ID_REQUIRED' }); const session = modelPipeline.snapshot(id); if (!session) return json(res, 404, { ok: false, code: 'MODEL_SCAN_NOT_FOUND' }); return json(res, 200, { ok: true, session }); }
    if (req.method === 'POST' && url.pathname === '/api/pro-scan/start') { const body = await readJson(req); if (typeof body.path !== 'string' || !body.path.trim()) return json(res, 400, { ok: false, code: 'PATH_REQUIRED' }); try { const entitlement = entitlementGate.requireModel('plus'); const session = modelPipeline.start(body.path, 'plus'); return json(res, 202, { ok: true, deprecated: true, mappedModel: 'plus', entitlement: { plan: entitlement.plan, source: entitlement.source }, session }); } catch (error) { if (error.code && error.code.startsWith('ENTITLEMENT_')) return entitlementDenied(res, error); throw error; } }
    if (req.method === 'GET' && url.pathname === '/api/pro-scan/status') { const id = url.searchParams.get('id'); if (!id) return json(res, 400, { ok: false, code: 'SCAN_ID_REQUIRED' }); const session = modelPipeline.snapshot(id); if (!session) return json(res, 404, { ok: false, code: 'PRO_SCAN_NOT_FOUND' }); return json(res, 200, { ok: true, deprecated: true, mappedModel: 'plus', session }); }
    if (req.method === 'GET' && url.pathname === '/api/access-gate/status') { ensureAgent(); return json(res, 200, await aclGate.status()); }
    if (req.method === 'POST' && url.pathname === '/api/access-gate/enable') { ensureAgent(); const result = await aclGate.protectAll(); return json(res, result.ok ? 200 : 409, result); }
    if (req.method === 'POST' && url.pathname === '/api/access-gate/disable') { ensureAgent(); const protection = protectionCoordinator.getCachedStatus(); if (protection.active) return json(res, 409, { ok:false, code:'ACCESS_GATE_REQUIRED_BY_ACTIVE_GUARD', protection }); return json(res, 200, await aclGate.restoreAll()); }
    if (req.method === 'GET' && url.pathname === '/api/guard/status') { ensureAgent(); return json(res, 200, await protectionCoordinator.status({ refresh:true })); }
    if (req.method === 'GET' && url.pathname === '/api/runtime-process/status') { ensureAgent(); return json(res, 200, { ok:true, runtimeProcessProtection:await runtimeProcessGuard.status({ refresh:runtimeProcessGuard.active === true }), capabilities:runtimeProcessGuard.capabilities() }); }
    if (req.method === 'POST' && url.pathname === '/api/guard/start') { ensureAgent(); const result = await protectionCoordinator.start(); return json(res, result.ok ? 200 : 409, result); }
    if (req.method === 'POST' && url.pathname === '/api/guard/stop') { if (!protectionCoordinator) return json(res, 200, { ok: true, active: false, completeProtection:false }); const result = await protectionCoordinator.stop(); return json(res, result.ok ? 200 : 409, result); }
    if (req.method === 'GET' && url.pathname === '/api/quarantine') { const a = ensureAgent(); return json(res, 200, { ok: true, entries: await a.listQuarantine() }); }
    if (req.method === 'POST' && url.pathname === '/api/quarantine/restore') { const body = await readJson(req); if (typeof body.id !== 'string') return json(res, 400, { ok: false, code: 'ID_REQUIRED' }); const a = ensureAgent(); return json(res, 200, { ok: true, entry: await a.restore(body.id) }); }
    if (req.method === 'POST' && url.pathname === '/api/install') { const body = await readJson(req); if (typeof body.source !== 'string' || typeof body.destination !== 'string') return json(res, 400, { ok: false, code: 'SOURCE_AND_DESTINATION_REQUIRED' }); ensureAgent(); return json(res, 200, await managedInstall.install(body.source, body.destination)); }
    if (req.method === 'GET' && url.pathname === '/api/incidents') return json(res, 200, { ok: true, incidents: await incidentStore.list(100) });
    if (req.method === 'GET' && url.pathname === '/api/sandbox/status') {
      const certification = sandbox.certificationStatus();
      const capabilities = await sandbox.windowsBackend.capabilities();
      return json(res, 200, { ok: true, certification, capabilities, selectedBackend: certification.selectedBackend || capabilities.selectedBackend || null });
    }
    if (req.method === 'POST' && url.pathname === '/api/sandbox/self-test') return json(res, 200, await sandbox.ensureRuntimeCertified({ force: true }));
    if (req.method === 'POST' && url.pathname === '/api/sandbox/readiness') return json(res, 200, await validationLab.run());
    if (req.method === 'POST' && url.pathname === '/api/sandbox/analyze') { const entitlement = requirePlanForApi(res, 'pro'); if (!entitlement) return; const body = await readJson(req); const result = await sandbox.analyzeUntrustedSample(body.path); return json(res, result.ok ? 200 : 409, result); }
    if (req.method === 'POST' && url.pathname === '/api/self-test') { const probe = await sandbox.ensureRuntimeCertified({ force: true }); const fixture = path.join(ROOT, 'tests', 'corpus', 'benign-config-read.lua'); const scan = await scanner.scanPath(fixture, 'pro'); return json(res, 200, { ok: probe.ok && scan.finalVerdict === 'safe', checks: { scanner: { ok: scan.finalVerdict === 'safe', verdict: scan.finalVerdict }, sandboxIsolationProbe: probe, guardConfiguration: { ok: config.watchRoots.length > 0, configured: config.watchRoots.length > 0 } } }); }
    if (req.method === 'GET' && await serveStatic(url.pathname, res)) return;
    json(res, 404, { ok: false, code: 'NOT_FOUND' });
  } catch (error) {
    await recordRuntimeError(error, { area: 'http', method: req.method, route: url.pathname });
    json(res, 500, { ok: false, code: 'INTERNAL_ERROR', message: 'Internal MalGuard error. See local diagnostics.' });
  }
}

function startServer(port = PORT) { const server = http.createServer(handler); return new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, HOST, () => resolve(server)); }); }

function installFatalErrorHandlers(reporter = errorReporter, exit = code => process.exit(code)) {
  let handlingFatal = false;
  const fatal = kind => async value => {
    if (handlingFatal) return exit(1);
    handlingFatal = true;
    const error = value instanceof Error ? value : new Error(safeText(value || kind));
    try { await reporter.record(error, { area: kind }); } catch (_) {}
    console.error(`MalGuard fatal ${kind}: ${safeText(error.code || error.name || 'INTERNAL_ERROR', 128)}`);
    exit(1);
  };
  const uncaughtException = fatal('uncaughtException');
  const unhandledRejection = fatal('unhandledRejection');
  process.once('uncaughtException', uncaughtException);
  process.once('unhandledRejection', unhandledRejection);
  return () => { process.removeListener('uncaughtException', uncaughtException); process.removeListener('unhandledRejection', unhandledRejection); };
}

if (require.main === module) {
  installFatalErrorHandlers();
  startServer().then(async () => {
    if (process.env.MALGUARD_SERVICE_MODE === '1') {
      if (!config.watchRoots.length) { const error = new Error('Windows service mode requires a configured protected game root.'); error.code = 'SERVICE_WATCH_ROOT_NOT_CONFIGURED'; throw error; }
      ensureAgent();
      const result = await protectionCoordinator.start();
      if (!result || result.ok !== true || result.completeProtection !== true || result.runtimeProcessHealthy !== true) { const error = new Error('Real-time protection failed to reach protected runtime healthy state during service startup.'); error.code = result && result.reason ? result.reason : 'SERVICE_GUARD_START_FAILED'; throw error; }
    }
    void recordFirstSuccessfulLaunch({
      version: DESKTOP_VERSION,
      settingsFile: settingsStore.filePath,
      packageRoot: ROOT,
    }).catch(() => {});
    void sendCompatibilityInstallReport({
      version: DESKTOP_VERSION,
      settingsFile: settingsStore.filePath,
      packageRoot: ROOT,
    }).catch(() => {});
    console.log(`MalGuard Desktop ${DESKTOP_VERSION} running at http://${HOST}:${PORT}`); console.log('Localhost only. No remote binding.');
  }).catch(async error => { await recordRuntimeError(error, { area: 'startup' }); console.error(`MalGuard startup failed: ${safeText(error.code || error.name || 'INTERNAL_ERROR', 128)}`); process.exit(1); });
}

module.exports = { startServer, handler, scanner, sandbox, validationLab, modelPipeline, proPipeline: modelPipeline, entitlementGate, errorReporter, recordRuntimeError, installFatalErrorHandlers, settingsStore, applySettings, getConfig: () => ({ ...config, watchRoots: [...config.watchRoots] }), getRealtimeProtectionStatus: () => protectionCoordinator ? protectionCoordinator.getCachedStatus() : { ok:false, active:false, completeProtection:false, state:'stopped' }, getRuntimeProcessProtectionStatus: () => runtimeProcessGuard ? runtimeProcessGuard.getCachedStatus() : { ok:false, active:false, healthy:false, state:'stopped' } };
