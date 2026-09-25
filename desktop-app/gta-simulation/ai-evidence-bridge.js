'use strict';

const AI_EVIDENCE_SCHEMA_VERSION = '1.1.0';
const ALLOWED_ACTIONS = new Set([
  'keep_blocked',
  'quarantine_sample',
  'review_evidence',
  'rescan_in_certified_sandbox',
]);
const ALLOWED_RISKS = new Set(['low', 'medium', 'high', 'unknown']);

function boundedString(value, max) {
  if (typeof value !== 'string') return null;
  return value.length <= max ? value : value.slice(0, max);
}

function boundedNumber(value, min, max) {
  if (!Number.isFinite(value)) return null;
  return Math.max(min, Math.min(max, Number(value)));
}

function summarizeFindings(items, maxItems = 32) {
  if (!Array.isArray(items)) return [];
  return items.slice(0, maxItems).map(item => ({
    rule: boundedString(item && item.rule || '', 80),
    category: boundedString(item && item.category || '', 80),
    severity: boundedString(item && item.severity || '', 24),
    confidence: boundedString(item && item.confidence || '', 24),
    weight: boundedNumber(item && item.weight, 0, 100),
  })).filter(item => item.rule || item.category);
}

function buildScannerEvidence(localResult) {
  if (!localResult || typeof localResult !== 'object') return null;
  const engine = localResult.engineResult && typeof localResult.engineResult === 'object'
    ? localResult.engineResult : null;
  const script = localResult.scriptAnalysis && typeof localResult.scriptAnalysis === 'object'
    ? localResult.scriptAnalysis : null;
  const archive = localResult.archiveInspection && typeof localResult.archiveInspection === 'object'
    ? localResult.archiveInspection : null;
  const multi = localResult.multiLayer && typeof localResult.multiLayer === 'object'
    ? localResult.multiLayer : null;
  const intel = localResult.threatIntel && typeof localResult.threatIntel === 'object'
    ? localResult.threatIntel : null;
  const pe = engine && engine.peSummary && typeof engine.peSummary === 'object' ? engine.peSummary : null;

  return {
    finalVerdict: localResult.finalVerdict || 'inconclusive',
    hardeningError: boundedString(localResult.hardeningError || '', 240),
    threatIntel: intel ? {
      status: boundedString(intel.status || '', 64),
      source: boundedString(intel.source || '', 32),
      signature: boundedString(intel.signature || '', 120),
      fileType: boundedString(intel.fileType || '', 48),
      tags: Array.isArray(intel.tags) ? intel.tags.slice(0, 12).map(v => boundedString(v, 48)).filter(Boolean) : [],
    } : null,
    detector: localResult.detectorResult && typeof localResult.detectorResult === 'object' ? {
      modType: boundedString(localResult.detectorResult.modType || '', 80),
      route: boundedString(localResult.detectorResult.route || '', 80),
      confidence: boundedString(localResult.detectorResult.confidence || '', 40),
      suspiciousPackaging: localResult.detectorResult.suspiciousPackaging === true,
    } : null,
    engine: engine ? {
      verdict: boundedString(engine.verdict || '', 32),
      score: boundedNumber(engine.score, 0, 100),
      confidence: boundedString(engine.confidence || '', 24),
      rulesStatus: boundedString(engine.rulesStatus || '', 32),
      peValid: engine.peValid === true,
      riskFloorApplied: boundedString(engine.riskFloorApplied || '', 32),
      gtaContextDetected: engine.gtaContextDetected === true,
      evidence: summarizeFindings(engine.evidence, 32),
      pe: pe ? {
        is64: pe.is64 === true,
        numberOfSections: boundedNumber(pe.numberOfSections, 0, 96),
        isDllFlagSet: pe.isDllFlagSet === true,
        entryPointSection: boundedString(pe.entryPointSection || '', 24),
        namedImportCount: boundedNumber(pe.namedImportCount, 0, 20000),
        ordinalImportCount: boundedNumber(pe.ordinalImportCount, 0, 20000),
        tlsPresent: !!(pe.tls && pe.tls.present),
        tlsCallbackCount: boundedNumber(pe.tls && pe.tls.callbackCount, 0, 64),
        overlayPresent: !!(pe.overlay && pe.overlay.present),
        overlaySize: boundedNumber(pe.overlay && pe.overlay.size, 0, 67108864),
        overlayEntropy: boundedNumber(pe.overlay && pe.overlay.entropy, 0, 8),
        securityDirectoryPresent: !!(pe.security && pe.security.present),
      } : null,
    } : null,
    script: script ? {
      verdict: boundedString(script.verdict || '', 32),
      confidence: boundedString(script.confidence || '', 24),
      score: boundedNumber(script.score, 0, 100),
      language: boundedString(script.language || '', 24),
      errorCode: boundedString(script.errorCode || '', 64),
      findings: summarizeFindings(script.evidence, 32),
      metrics: script.metrics && typeof script.metrics === 'object' ? {
        charCount: boundedNumber(script.metrics.charCount, 0, 4194304),
        lineCount: boundedNumber(script.metrics.lineCount, 0, 1000000),
        maxLineLength: boundedNumber(script.metrics.maxLineLength, 0, 1000000),
        veryLongLineCount: boundedNumber(script.metrics.veryLongLineCount, 0, 1000000),
      } : null,
      urlCount: Array.isArray(script.urls) ? Math.min(script.urls.length, 64) : 0,
      combinationRuleCount: Array.isArray(script.combinationRulesFired) ? Math.min(script.combinationRulesFired.length, 32) : 0,
    } : null,
    archive: archive ? {
      status: boundedString(archive.inspectionStatus || '', 64),
      type: boundedString(archive.archiveType || '', 24),
      pluginCount: boundedNumber(archive.pluginCount, 0, 10000),
      scriptCount: boundedNumber(archive.scriptCount, 0, 10000),
      nestedArchiveCount: boundedNumber(archive.nestedArchiveCount, 0, 10000),
      suspiciousPathCount: boundedNumber(archive.suspiciousPathCount, 0, 10000),
      doubleExtensionCount: boundedNumber(archive.doubleExtensionCount, 0, 10000),
      duplicatePathCount: boundedNumber(archive.duplicatePathCount, 0, 10000),
      possibleDecompressionBomb: archive.possibleDecompressionBomb === true,
    } : null,
    multiLayer: multi ? {
      verdict: boundedString(multi.finalVerdict || '', 32),
      decisionReason: boundedString(multi.decision && multi.decision.primaryReason || '', 96),
      conflict: !!(multi.conflict && multi.conflict.detected),
      gates: Array.isArray(multi.gates) ? multi.gates.slice(0, 12).map(g => ({
        gate: boundedString(g && g.gate || '', 48),
        result: boundedString(g && g.result || '', 24),
      })) : [],
    } : null,
  };
}

function normalizeActions(actions) {
  if (!Array.isArray(actions)) return [];
  return [...new Set(actions.filter(action => ALLOWED_ACTIONS.has(action)))].slice(0, 8);
}

function normalizeProviderResult(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { ok: false, code: 'AI_EVIDENCE_RESULT_INVALID' };
  }
  const risk = ALLOWED_RISKS.has(raw.risk) ? raw.risk : 'unknown';
  return {
    ok: true,
    risk,
    summary: boundedString(raw.summary || '', 600) || '',
    recommendedActions: normalizeActions(raw.recommendedActions),
  };
}

class AiEvidenceBridge {
  constructor({ provider = null, timeoutMs = 5000 } = {}) {
    this.provider = provider && typeof provider.analyzeEvidence === 'function' ? provider : null;
    this.timeoutMs = Math.max(250, Math.min(15000, Number(timeoutMs) || 5000));
  }

  capabilities() {
    const available = !!(this.provider && (typeof this.provider.available !== 'function' || this.provider.available() === true));
    return {
      schemaVersion: AI_EVIDENCE_SCHEMA_VERSION,
      available,
      provider: this.provider && this.provider.name ? String(this.provider.name).slice(0, 80) : null,
      onlineLearning: false,
      modelWeightsMutableDuringScan: false,
      autoRemediation: false,
      allowedRecommendedActions: [...ALLOWED_ACTIONS],
    };
  }

  async analyze({ model = 'standard', simulation = null, localResult = null } = {}) {
    const evidence = {
      schemaVersion: AI_EVIDENCE_SCHEMA_VERSION,
      model,
      simulation: simulation && typeof simulation === 'object' ? simulation : null,
      scanner: buildScannerEvidence(localResult),
    };

    if (!this.provider || (typeof this.provider.available === 'function' && this.provider.available() !== true)) {
      return {
        ok: true,
        available: false,
        status: this.provider ? 'provider_unavailable' : 'provider_not_configured',
        evidenceSchemaVersion: AI_EVIDENCE_SCHEMA_VERSION,
        onlineLearning: false,
        modelWeightsMutableDuringScan: false,
        autoRemediation: false,
        note: this.provider ? 'The AI evidence provider is configured but unavailable.' : 'The AI evidence interface is wired into the scan pipeline, but no real AI inference provider is packaged yet.',
      };
    }

    let timer;
    try {
      const timed = new Promise(resolve => {
        timer = setTimeout(() => resolve({ __timeout: true }), this.timeoutMs);
        if (typeof timer.unref === 'function') timer.unref();
      });
      const raw = await Promise.race([
        Promise.resolve().then(() => this.provider.analyzeEvidence(evidence)),
        timed,
      ]);
      if (raw && raw.__timeout === true) {
        return {
          ok: false,
          available: true,
          status: 'timeout',
          code: 'AI_EVIDENCE_TIMEOUT',
          onlineLearning: false,
          modelWeightsMutableDuringScan: false,
          autoRemediation: false,
        };
      }
      const normalized = normalizeProviderResult(raw);
      if (!normalized.ok) {
        return {
          ok: false,
          available: true,
          status: 'invalid_result',
          code: normalized.code,
          onlineLearning: false,
          modelWeightsMutableDuringScan: false,
          autoRemediation: false,
        };
      }
      return {
        ...normalized,
        available: true,
        status: 'completed',
        provider: this.provider.name ? String(this.provider.name).slice(0, 80) : 'configured-provider',
        onlineLearning: false,
        modelWeightsMutableDuringScan: false,
        autoRemediation: false,
      };
    } catch (_) {
      return {
        ok: false,
        available: true,
        status: 'provider_error',
        code: 'AI_EVIDENCE_PROVIDER_ERROR',
        onlineLearning: false,
        modelWeightsMutableDuringScan: false,
        autoRemediation: false,
      };
    } finally {
      if (timer) clearTimeout(timer);
    }
  }
}

module.exports = {
  AiEvidenceBridge,
  AI_EVIDENCE_SCHEMA_VERSION,
  ALLOWED_ACTIONS,
  normalizeProviderResult,
  buildScannerEvidence,
};
