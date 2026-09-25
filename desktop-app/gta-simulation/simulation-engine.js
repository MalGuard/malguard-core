'use strict';

const path = require('path');

const GTA_SIMULATION_VERSION = '0.1.0';
const RESULT_SCHEMA_VERSION = '1.0.0';

const MODEL_DEPTH = Object.freeze({
  standard: 'profile-only',
  plus: 'synthetic-runtime-model',
  pro: 'synthetic-runtime-model-plus-remediation',
});

const GTA_PLUGIN_EXTENSIONS = new Set(['.asi', '.dll']);

const SYNTHETIC_ENVIRONMENT = Object.freeze({
  game: 'Grand Theft Auto V',
  process: 'GTA5-Sim.exe',
  installRoot: 'C:\\MalGuardGtaSim\\Game',
  pluginRoot: 'C:\\MalGuardGtaSim\\Game\\plugins',
  scriptRoot: 'C:\\MalGuardGtaSim\\Game\\scripts',
  tempRoot: 'C:\\MalGuardGtaSim\\Temp',
  registryRoot: 'HKCU\\Software\\MalGuard\\GTA-Sim',
  userData: 'synthetic-only',
  networkPolicy: 'deny-all',
  realGameFilesMounted: false,
  realUserFilesMounted: false,
  directSampleExecution: false,
});

function normalizeModel(model) {
  return Object.prototype.hasOwnProperty.call(MODEL_DEPTH, model) ? model : 'standard';
}

function normalizeVerdict(value) {
  return ['safe', 'suspicious', 'malicious', 'inconclusive', 'invalid'].includes(value) ? value : 'inconclusive';
}

function boundedString(value, max = 160) {
  if (value == null) return null;
  const out = String(value);
  return out.length <= max ? out : out.slice(0, max);
}

function detectorFrom(localResult) {
  return localResult && localResult.detectorResult && typeof localResult.detectorResult === 'object'
    ? localResult.detectorResult
    : null;
}

function collectEvidence(localResult, extension) {
  const result = localResult && typeof localResult === 'object' ? localResult : {};
  const detector = detectorFrom(result);
  const verdict = normalizeVerdict(result.finalVerdict);
  const signals = [];

  if (detector && detector.suspiciousPackaging === true) signals.push('suspicious_packaging');
  if (verdict === 'malicious') signals.push('scanner_malicious');
  else if (verdict === 'suspicious') signals.push('scanner_suspicious');
  else if (verdict === 'inconclusive') signals.push('scanner_inconclusive');
  else if (verdict === 'invalid') signals.push('scanner_invalid');

  const intel = result.threatIntel;
  if (intel && intel.status === 'known_malicious') signals.push('known_malicious_hash');
  else if (intel && intel.status === 'unavailable') signals.push('threat_intel_unavailable');

  if (result.hardeningError) signals.push('scanner_hardening_limit');
  if (!GTA_PLUGIN_EXTENSIONS.has(extension)) signals.push('non_plugin_extension');

  return {
    scannerVerdict: verdict,
    contentSha256: boundedString(result.contentSha256 || (result.sourceIdentity && result.sourceIdentity.sha256), 64),
    modType: detector ? boundedString(detector.modType, 64) : (GTA_PLUGIN_EXTENSIONS.has(extension) ? 'plugin' : 'unknown'),
    detectorRoute: detector ? boundedString(detector.route, 64) : null,
    detectorConfidence: detector ? boundedString(detector.confidence, 32) : null,
    suspiciousPackaging: !!(detector && detector.suspiciousPackaging === true),
    threatIntelStatus: intel ? boundedString(intel.status, 64) : 'unknown',
    hardeningError: boundedString(result.hardeningError, 128),
    signals,
  };
}

function buildRemediationPlan(evidence, model) {
  const risk = evidence.scannerVerdict;
  const actions = [];

  if (risk === 'malicious') {
    actions.push('keep_blocked', 'quarantine_sample', 'review_evidence');
  } else if (risk === 'suspicious') {
    actions.push('keep_blocked', 'review_evidence', 'rescan_in_certified_sandbox');
  } else if (risk === 'inconclusive' || risk === 'invalid') {
    actions.push('keep_blocked', 'review_evidence');
  } else {
    actions.push('review_evidence');
  }

  if (model === 'standard') {
    return {
      available: false,
      reason: 'remediation_planning_requires_plus_or_pro',
      actions: [],
      autoApply: false,
      hostMutationAllowed: false,
      userApprovalRequired: true,
    };
  }

  return {
    available: true,
    actions: [...new Set(actions)],
    autoApply: false,
    hostMutationAllowed: false,
    userApprovalRequired: true,
    note: 'This is a defensive plan only. It never deletes or edits host files automatically.',
  };
}

class GtaSimulationEngine {
  constructor() {
    this.version = GTA_SIMULATION_VERSION;
  }

  capabilities() {
    return {
      ok: true,
      version: GTA_SIMULATION_VERSION,
      modes: Object.keys(MODEL_DEPTH),
      environment: { ...SYNTHETIC_ENVIRONMENT },
      untrustedCodeExecution: false,
      verdictPolicy: {
        canPromoteSafe: false,
        canRaiseRisk: false,
        advisoryOnly: true,
      },
    };
  }

  analyze({ filePath, localResult = null, model = 'standard' } = {}) {
    const normalizedModel = normalizeModel(model);
    const extension = path.extname(String(filePath || '')).toLowerCase();
    const evidence = collectEvidence(localResult, extension);
    const isPlugin = GTA_PLUGIN_EXTENSIONS.has(extension) || evidence.modType === 'plugin';

    return {
      ok: true,
      schemaVersion: RESULT_SCHEMA_VERSION,
      simulationVersion: GTA_SIMULATION_VERSION,
      model: normalizedModel,
      depth: MODEL_DEPTH[normalizedModel],
      environment: { ...SYNTHETIC_ENVIRONMENT },
      sampleProfile: {
        extension: boundedString(extension, 32),
        modType: evidence.modType,
        gtaPluginCandidate: isPlugin,
        directExecutionAttempted: false,
      },
      evidence,
      simulatedInteractions: {
        processHost: 'GTA5-Sim.exe',
        pluginDirectoryAvailable: true,
        scriptDirectoryAvailable: true,
        syntheticRegistryAvailable: normalizedModel !== 'standard',
        syntheticNetworkAvailable: false,
        hostFilesystemAvailable: false,
      },
      remediationPlan: buildRemediationPlan(evidence, normalizedModel),
      verdictPolicy: {
        advisoryOnly: true,
        canPromoteSafe: false,
        canRaiseRisk: false,
        reason: 'Synthetic GTA simulation context is not real execution proof.',
      },
    };
  }
}

module.exports = {
  GtaSimulationEngine,
  GTA_SIMULATION_VERSION,
  RESULT_SCHEMA_VERSION,
  MODEL_DEPTH,
  GTA_PLUGIN_EXTENSIONS,
  SYNTHETIC_ENVIRONMENT,
  collectEvidence,
  buildRemediationPlan,
};
