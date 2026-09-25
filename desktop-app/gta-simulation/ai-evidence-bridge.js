'use strict';

const AI_EVIDENCE_SCHEMA_VERSION = '1.0.0';
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
      scanner: localResult && typeof localResult === 'object'
        ? {
            finalVerdict: localResult.finalVerdict || 'inconclusive',
            hardeningError: localResult.hardeningError || null,
            threatIntelStatus: localResult.threatIntel && localResult.threatIntel.status || null,
          }
        : null,
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
};
