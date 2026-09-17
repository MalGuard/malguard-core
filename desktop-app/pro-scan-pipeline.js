'use strict';

const crypto = require('crypto');
const path = require('path');

const PIPELINE_VERSION = '1.3.0';
const MAX_EVENTS = 64;
const DEFAULT_TTL_MS = 10 * 60 * 1000;
const MODELS = Object.freeze(['standard', 'plus', 'pro']);

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function normalizeVerdict(value) {
  return ['safe', 'suspicious', 'malicious', 'inconclusive'].includes(value) ? value : 'inconclusive';
}

function normalizeModel(value) {
  return MODELS.includes(value) ? value : null;
}

function shouldSandbox(verdict) {
  return verdict === 'suspicious' || verdict === 'inconclusive';
}

function sandboxExecutionProven(sandboxResult) {
  return !!(sandboxResult
    && sandboxResult.ok === true
    && sandboxResult.sandboxLaunched === true
    && sandboxResult.sampleExecutionStarted === true);
}

function mergeSandboxVerdict(localVerdict, sandboxResult) {
  const local = normalizeVerdict(localVerdict);
  if (!sandboxExecutionProven(sandboxResult)) return local;
  const sandboxVerdict = normalizeVerdict(sandboxResult && sandboxResult.verdict);
  if (local === 'malicious' || sandboxVerdict === 'malicious') return 'malicious';
  if (local === 'suspicious') return 'suspicious';
  if (sandboxVerdict === 'suspicious') return 'suspicious';
  if (local === 'inconclusive') return 'inconclusive';
  return local;
}

function directSandboxVerdict(sandboxResult) {
  if (!sandboxExecutionProven(sandboxResult)) return 'inconclusive';
  const verdict = normalizeVerdict(sandboxResult && sandboxResult.verdict);
  if (verdict === 'malicious' || verdict === 'suspicious') return verdict;
  if (verdict === 'safe' && sandboxResult.releaseGrade === true) return 'safe';
  return 'inconclusive';
}

function fallbackVerdict(localVerdict) {
  const verdict = normalizeVerdict(localVerdict);
  if (verdict === 'malicious' || verdict === 'suspicious') return verdict;
  // Missing behavioral execution proof means a clean fallback scan may not upgrade to SAFE.
  return 'inconclusive';
}

class ModelScanPipelineManager {
  constructor({ scanner, sandbox, now = () => Date.now(), ttlMs = DEFAULT_TTL_MS, maxSessions = 32 } = {}) {
    if (!scanner || typeof scanner.scanPath !== 'function') throw new TypeError('scanner.scanPath is required');
    if (!sandbox || typeof sandbox.analyzeUntrustedSample !== 'function') throw new TypeError('sandbox.analyzeUntrustedSample is required');
    if (typeof sandbox.preflightSample !== 'function') throw new TypeError('sandbox.preflightSample is required');
    this.scanner = scanner;
    this.sandbox = sandbox;
    this.now = now;
    this.ttlMs = Math.max(30_000, Number(ttlMs) || DEFAULT_TTL_MS);
    this.maxSessions = Math.max(4, Number(maxSessions) || 32);
    this.sessions = new Map();
  }

  _prune() {
    const cutoff = this.now() - this.ttlMs;
    for (const [id, session] of this.sessions) {
      if (session.updatedAt < cutoff) this.sessions.delete(id);
    }
    while (this.sessions.size >= this.maxSessions) {
      const oldest = [...this.sessions.values()].sort((a, b) => a.updatedAt - b.updatedAt)[0];
      if (!oldest) break;
      this.sessions.delete(oldest.id);
    }
  }

  _emit(session, phase, status, message, details = null) {
    const event = {
      seq: session.nextSeq++,
      phase,
      status,
      message,
      at: new Date(this.now()).toISOString(),
    };
    if (details != null) event.details = details;
    session.events.push(event);
    if (session.events.length > MAX_EVENTS) session.events.splice(0, session.events.length - MAX_EVENTS);
    session.updatedAt = this.now();
    return event;
  }

  start(filePath, model = 'plus') {
    if (typeof filePath !== 'string' || !filePath.trim()) {
      const error = new Error('scan path is required');
      error.code = 'PATH_REQUIRED';
      throw error;
    }
    const normalizedModel = normalizeModel(String(model || '').toLowerCase());
    if (!normalizedModel) {
      const error = new Error('model must be standard, plus or pro');
      error.code = 'INVALID_MODEL';
      throw error;
    }

    this._prune();
    const id = crypto.randomUUID();
    const session = {
      id,
      pipelineVersion: PIPELINE_VERSION,
      model: normalizedModel,
      filePath: path.resolve(filePath),
      state: 'queued',
      createdAt: this.now(),
      updatedAt: this.now(),
      nextSeq: 1,
      events: [],
      localResult: null,
      preflight: null,
      sandboxResult: null,
      fallbackResult: null,
      finalResult: null,
      error: null,
    };
    this.sessions.set(id, session);
    this._emit(session, 'prepare', 'queued', normalizedModel === 'pro'
      ? 'Preparing direct Pro Sandbox analysis'
      : normalizedModel === 'plus'
        ? 'Preparing Plus deep scan'
        : 'Preparing Standard scan');

    Promise.resolve().then(() => this._run(session)).catch(error => {
      session.state = 'failed';
      session.error = { code: error.code || 'MODEL_PIPELINE_ERROR', message: error.message || 'Model pipeline failed' };
      this._emit(session, 'final_verdict', 'failed', `${session.model} scan failed closed`, session.error);
      session.finalResult = {
        model: session.model,
        verdict: 'inconclusive',
        completionState: 'failed_closed',
        sandboxRequested: session.model === 'pro',
        sandboxStarted: false,
        sampleExecutionStarted: false,
        error: session.error,
      };
    });
    return this.snapshot(id);
  }

  snapshot(id) {
    const session = this.sessions.get(String(id || ''));
    if (!session) return null;
    const out = clone(session);
    delete out.nextSeq;
    return out;
  }

  async _run(session) {
    session.state = 'running';
    if (session.model === 'standard') return this._runStandard(session);
    if (session.model === 'plus') return this._runPlus(session);
    return this._runPro(session);
  }

  async _runStandard(session) {
    this._emit(session, 'standard_scan', 'running', 'Running Standard local scan');
    const local = await this.scanner.scanPath(session.filePath, 'free');
    session.localResult = clone(local);
    const verdict = normalizeVerdict(local && local.finalVerdict);
    this._emit(session, 'standard_scan', 'completed', 'Standard scan completed', {
      verdict,
      sha256: local && local.contentSha256 ? local.contentSha256 : (local && local.sourceIdentity ? local.sourceIdentity.sha256 : null),
    });
    session.finalResult = {
      model: 'standard',
      verdict,
      completionState: 'complete',
      sandboxRequested: false,
      localResult: clone(local),
    };
    session.state = 'completed';
    this._emit(session, 'final_verdict', 'completed', `Final verdict: ${verdict.toUpperCase()}`, { verdict, model: 'standard' });
  }

  async _runPlus(session) {
    this._emit(session, 'prepare', 'running', 'Validating file and preparing Plus deep scanner');
    this._emit(session, 'static_scan', 'running', 'Running local deep static analysis');
    const local = await this.scanner.scanPath(session.filePath, 'pro');
    session.localResult = clone(local);
    const localVerdict = normalizeVerdict(local && local.finalVerdict);
    this._emit(session, 'static_scan', 'completed', 'Deep static analysis completed', {
      verdict: localVerdict,
      sha256: local && local.contentSha256 ? local.contentSha256 : (local && local.sourceIdentity ? local.sourceIdentity.sha256 : null),
    });

    if (local && local.archiveInspection) {
      this._emit(session, 'archive_analysis', 'completed', 'Archive inspection completed', {
        verdict: local.archiveInspection.finalVerdict || null,
      });
    }
    if (local && local.scriptAnalysis) {
      this._emit(session, 'script_analysis', 'completed', 'Script analysis completed', {
        verdict: local.scriptAnalysis.finalVerdict || null,
      });
    }
    this._emit(session, 'correlation', 'completed', local && local.multiLayer
      ? 'Multi-layer signal correlation completed'
      : 'Scanner evidence correlation completed');

    const intel = local && local.threatIntel ? local.threatIntel : { status: 'disabled' };
    this._emit(session, 'threat_intelligence', 'completed', 'Threat-intelligence check completed', {
      status: intel.status || 'unknown',
      source: intel.source || null,
    });

    if (!shouldSandbox(localVerdict)) {
      this._emit(session, 'sandbox_decision', 'completed', localVerdict === 'malicious'
        ? 'Sandbox skipped: local evidence is already malicious'
        : 'Sandbox not required for this result', { requested: false, localVerdict });
      session.finalResult = {
        model: 'plus',
        verdict: localVerdict,
        completionState: 'complete',
        sandboxRequested: false,
        localResult: clone(local),
      };
      session.state = 'completed';
      this._emit(session, 'final_verdict', 'completed', `Final verdict: ${localVerdict.toUpperCase()}`, { verdict: localVerdict, model: 'plus' });
      return;
    }

    this._emit(session, 'sandbox_decision', 'warning', 'Suspicious or inconclusive result detected. Send to Sandbox.', {
      requested: true,
      localVerdict,
    });
    this._emit(session, 'sandbox_analysis', 'running', 'Sending sample to isolated Sandbox backend');
    const sandboxResult = await this.sandbox.analyzeUntrustedSample(session.filePath);
    session.sandboxResult = clone(sandboxResult);
    const sandboxStarted = !!(sandboxResult && sandboxResult.sandboxLaunched === true);
    const sampleExecutionStarted = !!(sandboxResult && sandboxResult.sampleExecutionStarted === true);
    const executionProven = sandboxExecutionProven(sandboxResult);

    if (!executionProven) {
      const code = sandboxResult && sandboxResult.code
        ? sandboxResult.code
        : sandboxResult && sandboxResult.ok === true
          ? 'SANDBOX_EXECUTION_PROOF_MISSING'
          : 'SANDBOX_UNAVAILABLE';
      this._emit(session, 'sandbox_analysis', 'blocked', 'Sandbox analysis could not prove real isolated execution; keeping fail-closed result', {
        code,
        sandboxStarted,
        sampleExecutionStarted,
      });
      const finalVerdict = localVerdict === 'suspicious' ? 'suspicious' : 'inconclusive';
      session.finalResult = {
        model: 'plus',
        verdict: finalVerdict,
        completionState: 'sandbox_unavailable_fail_closed',
        sandboxRequested: true,
        sandboxStarted,
        sampleExecutionStarted,
        sandboxCompleted: false,
        localResult: clone(local),
        sandboxResult: clone(sandboxResult || { ok: false, verdict: 'inconclusive' }),
      };
      session.state = 'completed';
      this._emit(session, 'final_verdict', 'completed', `Final verdict: ${finalVerdict.toUpperCase()}`, {
        verdict: finalVerdict,
        model: 'plus',
        sandboxRequired: true,
        sandboxStarted,
        sampleExecutionStarted,
        sandboxCompleted: false,
      });
      return;
    }

    const finalVerdict = mergeSandboxVerdict(localVerdict, sandboxResult);
    this._emit(session, 'sandbox_analysis', 'completed', 'Sandbox behavior analysis completed with real execution proof', {
      verdict: normalizeVerdict(sandboxResult.verdict),
      backend: sandboxResult.backend && sandboxResult.backend.backend ? sandboxResult.backend.backend : null,
      sandboxStarted: true,
      sampleExecutionStarted: true,
    });
    session.finalResult = {
      model: 'plus',
      verdict: finalVerdict,
      completionState: 'complete',
      sandboxRequested: true,
      sandboxStarted: true,
      sampleExecutionStarted: true,
      sandboxCompleted: true,
      localResult: clone(local),
      sandboxResult: clone(sandboxResult),
    };
    session.state = 'completed';
    this._emit(session, 'final_verdict', 'completed', `Final verdict: ${finalVerdict.toUpperCase()}`, {
      verdict: finalVerdict,
      model: 'plus',
      sandboxRequired: true,
      sandboxStarted: true,
      sampleExecutionStarted: true,
      sandboxCompleted: true,
    });
  }

  async _runFallbackDeepScan(session, reasonCode) {
    this._emit(session, 'fallback_analysis', 'running', 'Sandbox unavailable; running fail-closed deep fallback analysis', { reasonCode });
    try {
      const local = await this.scanner.scanPath(session.filePath, 'pro');
      session.localResult = clone(local);
      const localVerdict = normalizeVerdict(local && local.finalVerdict);
      const verdict = fallbackVerdict(localVerdict);
      const engines = {
        deepStatic: true,
        multiLayer: !!(local && local.multiLayer),
        archive: !!(local && local.archiveInspection),
        script: !!(local && local.scriptAnalysis),
        threatIntel: !!(local && local.threatIntel),
      };
      session.fallbackResult = {
        ok: true,
        reasonCode,
        localVerdict,
        verdict,
        engines,
        localResult: clone(local),
      };
      this._emit(session, 'fallback_analysis', 'completed', 'Deep fallback analysis completed', {
        localVerdict,
        verdict,
        engines,
      });
      return session.fallbackResult;
    } catch (error) {
      const failure = {
        ok: false,
        reasonCode,
        verdict: 'inconclusive',
        error: { code: error.code || 'FALLBACK_ANALYSIS_FAILED', message: error.message || 'fallback analysis failed' },
      };
      session.fallbackResult = failure;
      this._emit(session, 'fallback_analysis', 'failed', 'Deep fallback analysis also failed closed', failure.error);
      return failure;
    }
  }

  async _runPro(session) {
    this._emit(session, 'preflight', 'running', 'Validating sample before direct Sandbox handoff');
    const preflight = await this.sandbox.preflightSample(session.filePath);
    session.preflight = clone(preflight);
    if (!preflight || preflight.ok !== true) {
      const code = preflight && preflight.code ? preflight.code : 'SANDBOX_PREFLIGHT_FAILED';
      this._emit(session, 'preflight', 'blocked', 'Pro Sandbox preflight failed closed', { code });
      const fallback = await this._runFallbackDeepScan(session, code);
      session.finalResult = {
        model: 'pro',
        verdict: fallback.verdict,
        completionState: 'preflight_failed_fallback_complete',
        sandboxRequested: true,
        sandboxStarted: false,
        sampleExecutionStarted: false,
        sandboxCompleted: false,
        fallbackUsed: true,
        preflight: clone(preflight || { ok: false, code }),
        fallbackResult: clone(fallback),
      };
      session.state = 'completed';
      this._emit(session, 'final_verdict', 'completed', `Final verdict: ${fallback.verdict.toUpperCase()}`, {
        verdict: fallback.verdict, model: 'pro', sandboxStarted: false, sampleExecutionStarted: false, sandboxCompleted: false, fallbackUsed: true,
      });
      return;
    }

    this._emit(session, 'preflight', 'completed', 'Sample validated for direct Sandbox analysis', {
      sha256: preflight.sha256,
      size: preflight.size,
      extension: preflight.extension,
    });
    this._emit(session, 'sandbox_analysis', 'running', 'Sending sample directly to isolated Sandbox');
    const sandboxResult = await this.sandbox.analyzeUntrustedSample(session.filePath);
    session.sandboxResult = clone(sandboxResult);
    const sandboxStarted = !!(sandboxResult && sandboxResult.sandboxLaunched === true);
    const sampleExecutionStarted = !!(sandboxResult && sandboxResult.sampleExecutionStarted === true);
    const executionProven = sandboxExecutionProven(sandboxResult);

    if (!executionProven) {
      const code = sandboxResult && sandboxResult.code
        ? sandboxResult.code
        : sandboxResult && sandboxResult.ok === true
          ? 'SANDBOX_EXECUTION_PROOF_MISSING'
          : 'SANDBOX_UNAVAILABLE';
      this._emit(session, 'sandbox_analysis', 'blocked', 'Direct Sandbox analysis could not prove real isolated execution; starting deep fallback analysis', {
        code,
        sandboxStarted,
        sampleExecutionStarted,
      });
      const fallback = await this._runFallbackDeepScan(session, code);
      session.finalResult = {
        model: 'pro',
        verdict: fallback.verdict,
        completionState: 'sandbox_unavailable_fallback_complete',
        sandboxRequested: true,
        sandboxStarted,
        sampleExecutionStarted,
        sandboxCompleted: false,
        fallbackUsed: true,
        preflight: clone(preflight),
        sandboxResult: clone(sandboxResult || { ok: false, verdict: 'inconclusive' }),
        fallbackResult: clone(fallback),
      };
      session.state = 'completed';
      this._emit(session, 'final_verdict', 'completed', `Final verdict: ${fallback.verdict.toUpperCase()}`, {
        verdict: fallback.verdict, model: 'pro', sandboxStarted, sampleExecutionStarted, sandboxCompleted: false, fallbackUsed: true,
      });
      return;
    }

    const finalVerdict = directSandboxVerdict(sandboxResult);
    this._emit(session, 'sandbox_analysis', 'completed', 'Direct Sandbox behavior analysis completed with real execution proof', {
      verdict: normalizeVerdict(sandboxResult.verdict),
      releaseGrade: sandboxResult.releaseGrade === true,
      backend: sandboxResult.backend && sandboxResult.backend.backend ? sandboxResult.backend.backend : null,
      sandboxStarted: true,
      sampleExecutionStarted: true,
    });
    session.finalResult = {
      model: 'pro',
      verdict: finalVerdict,
      completionState: 'complete',
      sandboxRequested: true,
      sandboxStarted: true,
      sampleExecutionStarted: true,
      sandboxCompleted: true,
      fallbackUsed: false,
      preflight: clone(preflight),
      sandboxResult: clone(sandboxResult),
    };
    session.state = 'completed';
    this._emit(session, 'final_verdict', 'completed', `Final verdict: ${finalVerdict.toUpperCase()}`, {
      verdict: finalVerdict, model: 'pro', sandboxStarted: true, sampleExecutionStarted: true, sandboxCompleted: true, fallbackUsed: false,
    });
  }
}

class ProScanPipelineManager extends ModelScanPipelineManager {
  start(filePath) {
    return super.start(filePath, 'plus');
  }
}

module.exports = {
  ModelScanPipelineManager,
  ProScanPipelineManager,
  PIPELINE_VERSION,
  MODELS,
  normalizeModel,
  normalizeVerdict,
  shouldSandbox,
  sandboxExecutionProven,
  mergeSandboxVerdict,
  directSandboxVerdict,
  fallbackVerdict,
};