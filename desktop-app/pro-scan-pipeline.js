'use strict';

const crypto = require('crypto');
const path = require('path');

const PIPELINE_VERSION = '1.6.0';
const MAX_EVENTS = 64;
const DEFAULT_TTL_MS = 10 * 60 * 1000;
const MODELS = Object.freeze(['standard', 'plus', 'pro']);
const GTA_PLUGIN_EXTENSIONS = new Set(['.asi', '.dll']);

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

function deepStaticFallbackVerdict(localResult) {
  const verdict = normalizeVerdict(localResult && localResult.finalVerdict);
  if (verdict === 'malicious' || verdict === 'suspicious') return verdict;
  // Without dynamic execution, fallback analysis never upgrades a sample to SAFE.
  return 'inconclusive';
}

class ModelScanPipelineManager {
  constructor({ scanner, sandbox, cloudInspection = null, gtaCloudSimulation = null, gtaSimulation = null, aiEvidence = null, now = () => Date.now(), ttlMs = DEFAULT_TTL_MS, maxSessions = 32 } = {}) {
    if (!scanner || typeof scanner.scanPath !== 'function') throw new TypeError('scanner.scanPath is required');
    if (!sandbox || typeof sandbox.analyzeUntrustedSample !== 'function') throw new TypeError('sandbox.analyzeUntrustedSample is required');
    if (typeof sandbox.preflightSample !== 'function') throw new TypeError('sandbox.preflightSample is required');
    this.scanner = scanner;
    this.sandbox = sandbox;
    this.cloudInspection = cloudInspection && typeof cloudInspection.inspect === 'function' ? cloudInspection : null;
    this.gtaCloudSimulation = gtaCloudSimulation && typeof gtaCloudSimulation.simulate === 'function' ? gtaCloudSimulation : null;
    this.gtaSimulation = gtaSimulation && typeof gtaSimulation.analyze === 'function' ? gtaSimulation : null;
    this.aiEvidence = aiEvidence && typeof aiEvidence.analyze === 'function' ? aiEvidence : null;
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

  start(filePath, model = 'plus', { onFinish = null, allowCloudFallback = false, allowAiEvidence = false } = {}) {
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
      cloudInspectionResult: null,
      gtaCloudSimulationResult: null,
      gtaSimulationResult: null,
      aiEvidenceResult: null,
      allowCloudFallback: allowCloudFallback === true,
      allowAiEvidence: allowAiEvidence === true,
      finalResult: null,
      error: null,
    };
    this.sessions.set(id, session);
    this._emit(session, 'prepare', 'queued', normalizedModel === 'pro'
      ? 'Preparing Pro Sandbox analysis with deep static fallback'
      : normalizedModel === 'plus'
        ? 'Preparing Plus deep scan'
        : 'Preparing Standard scan');

    const run = Promise.resolve().then(() => this._run(session)).catch(error => {
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
    if (onFinish) void run.finally(() => Promise.resolve().then(onFinish).catch(() => {}));
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
    if (session.model === 'standard') await this._runStandard(session);
    else if (session.model === 'plus') await this._runPlus(session);
    else await this._runPro(session);
    await this._attachGtaSimulationAndAiEvidence(session);
  }

  async _attachGtaSimulationAndAiEvidence(session) {
    if (!session || !session.finalResult) return;

    if (this.gtaSimulation) {
      try {
        this._emit(session, 'gta_simulation', 'running', 'Building synthetic GTA runtime context from scan evidence');
        const simulation = await Promise.resolve(this.gtaSimulation.analyze({
          filePath: session.filePath,
          localResult: session.localResult,
          model: session.model,
        }));
        session.gtaSimulationResult = clone(simulation);
        session.finalResult.gtaSimulation = clone(simulation);
        this._emit(session, 'gta_simulation', 'completed', 'Synthetic GTA runtime context completed without executing the sample', {
          depth: simulation && simulation.depth || null,
          directExecutionAttempted: !!(simulation && simulation.sampleProfile && simulation.sampleProfile.directExecutionAttempted),
          canPromoteSafe: !!(simulation && simulation.verdictPolicy && simulation.verdictPolicy.canPromoteSafe),
        });
      } catch (error) {
        const failure = { ok: false, code: error && error.code || 'GTA_SIMULATION_FAILED' };
        session.gtaSimulationResult = failure;
        session.finalResult.gtaSimulation = failure;
        this._emit(session, 'gta_simulation', 'blocked', 'Synthetic GTA runtime context failed closed', failure);
      }
    }

    if (this.aiEvidence) {
      if (session.allowAiEvidence !== true) {
        const capabilities = typeof this.aiEvidence.capabilities === 'function' ? this.aiEvidence.capabilities() : { available: false };
        const skipped = {
          ok: true,
          available: capabilities.available === true,
          status: 'not_requested',
          onlineLearning: false,
          modelWeightsMutableDuringScan: false,
          autoRemediation: false,
        };
        session.aiEvidenceResult = skipped;
        session.finalResult.aiEvidence = skipped;
        this._emit(session, 'ai_evidence', 'warning', 'MalGuard AI evidence analysis is available but was not requested', {
          available: skipped.available,
          status: skipped.status,
          fileBytesShared: false,
        });
      } else {
        try {
          this._emit(session, 'ai_evidence', 'running', 'Sending bounded metadata-only evidence to MalGuard AI');
          const ai = await this.aiEvidence.analyze({
            model: session.model,
            simulation: { local: session.gtaSimulationResult, isolated: session.gtaCloudSimulationResult },
            localResult: session.localResult,
          });
          session.aiEvidenceResult = clone(ai);
          session.finalResult.aiEvidence = clone(ai);
          this._emit(session, 'ai_evidence', ai && ai.ok === true ? 'completed' : 'blocked',
            ai && ai.ok === true
              ? 'MalGuard AI evidence analysis completed'
              : 'MalGuard AI evidence analysis failed closed', {
              available: !!(ai && ai.available === true),
              status: ai && ai.status || null,
              risk: ai && ai.risk || null,
              onlineLearning: !!(ai && ai.onlineLearning === true),
              autoRemediation: !!(ai && ai.autoRemediation === true),
              fileBytesShared: false,
            });
        } catch (error) {
          const failure = {
            ok: false,
            available: false,
            status: 'bridge_error',
            code: error && error.code || 'AI_EVIDENCE_BRIDGE_FAILED',
            onlineLearning: false,
            autoRemediation: false,
          };
          session.aiEvidenceResult = failure;
          session.finalResult.aiEvidence = failure;
          this._emit(session, 'ai_evidence', 'blocked', 'MalGuard AI evidence bridge failed closed', failure);
        }
      }
    }
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

  async _runDeepStaticFallback(session, { model, reasonCode, existingLocal = null, preflight = null, sandboxResult = null, sandboxStarted = false, sampleExecutionStarted = false, pluginDirectExecutionUnsupported = false } = {}) {
    this._emit(session, 'fallback_analysis', 'running', 'Local behavioral Sandbox unavailable; running deep non-executing fallback analysis', {
      reasonCode: reasonCode || 'SANDBOX_UNAVAILABLE',
      executionMode: 'no_dynamic_execution',
      cloudFallbackRequested: session.allowCloudFallback === true,
    });

    const local = existingLocal || await this.scanner.scanPath(session.filePath, 'pro');
    session.localResult = clone(local);
    const finalVerdict = deepStaticFallbackVerdict(local);

    let cloudInspectionResult = null;
    let gtaCloudSimulationResult = null;
    if (session.allowCloudFallback === true && pluginDirectExecutionUnsupported && this.gtaCloudSimulation) {
      this._emit(session, 'gta_cloud_simulation', 'running', 'Creating a disposable isolated GTA simulation environment', {
        execution: 'no-sample-execution',
        retention: 'destroy-after-run',
      });
      gtaCloudSimulationResult = await this.gtaCloudSimulation.simulate(session.filePath);
      session.gtaCloudSimulationResult = clone(gtaCloudSimulationResult);
      cloudInspectionResult = gtaCloudSimulationResult;
      session.cloudInspectionResult = clone(gtaCloudSimulationResult);
      if (gtaCloudSimulationResult && gtaCloudSimulationResult.ok === true) {
        this._emit(session, 'gta_cloud_simulation', 'completed', 'Disposable isolated GTA simulation completed; environment destroyed after the job', {
          treeReady: !!(gtaCloudSimulationResult.report && gtaCloudSimulationResult.report.treeReady),
          sampleExecutionAttempted: false,
          destroyAfterRun: true,
        });
      } else {
        this._emit(session, 'gta_cloud_simulation', 'blocked', 'Isolated GTA simulation was unavailable; local fail-closed result preserved', {
          code: gtaCloudSimulationResult && gtaCloudSimulationResult.code || 'GTA_CLOUD_SIMULATION_UNAVAILABLE',
          sampleExecutionAttempted: false,
        });
      }
    } else if (session.allowCloudFallback === true && this.cloudInspection) {
      this._emit(session, 'cloud_ephemeral_inspection', 'running', 'Uploading a bounded copy for disposable cloud inspection', {
        execution: 'inspection-only',
        retention: 'destroy-after-run',
      });
      cloudInspectionResult = await this.cloudInspection.inspect(session.filePath);
      session.cloudInspectionResult = clone(cloudInspectionResult);
      if (cloudInspectionResult && cloudInspectionResult.ok === true) {
        this._emit(session, 'cloud_ephemeral_inspection', 'completed', 'Disposable cloud inspection completed; environment destroyed after the job', {
          type: cloudInspectionResult.report && cloudInspectionResult.report.type || 'unknown',
          executionAttempted: false,
          destroyAfterRun: true,
        });
      } else {
        this._emit(session, 'cloud_ephemeral_inspection', 'blocked', 'Cloud inspection was unavailable; local fail-closed result preserved', {
          code: cloudInspectionResult && cloudInspectionResult.code || 'CLOUD_INSPECTION_UNAVAILABLE',
          executionAttempted: false,
        });
      }
    }

    if (local && local.archiveInspection) {
      this._emit(session, 'fallback_archive_analysis', 'completed', 'Fallback archive inspection completed', {
        verdict: local.archiveInspection.finalVerdict || null,
      });
    }
    if (local && local.scriptAnalysis) {
      this._emit(session, 'fallback_script_analysis', 'completed', 'Fallback script analysis completed', {
        verdict: local.scriptAnalysis.finalVerdict || null,
      });
    }
    const intel = local && local.threatIntel ? local.threatIntel : { status: 'disabled' };
    this._emit(session, 'fallback_threat_intelligence', 'completed', 'Fallback threat-intelligence check completed', {
      status: intel.status || 'unknown',
      source: intel.source || null,
    });
    this._emit(session, 'fallback_analysis', 'completed', 'Deep fallback analysis completed without executing the sample', {
      verdict: finalVerdict,
      limitation: 'dynamic behavior unavailable',
    });

    session.finalResult = {
      model,
      verdict: finalVerdict,
      completionState: 'deep_static_fallback',
      sandboxRequested: true,
      sandboxStarted,
      sampleExecutionStarted,
      sandboxCompleted: false,
      fallbackUsed: true,
      fallbackMode: 'deep_static_no_execution',
      dynamicAnalysisUnavailable: true,
      pluginDirectExecutionUnsupported: pluginDirectExecutionUnsupported === true,
      cloudFallbackRequested: session.allowCloudFallback === true,
      cloudInspectionCompleted: !!(cloudInspectionResult && cloudInspectionResult.ok === true),
      gtaCloudSimulationCompleted: !!(gtaCloudSimulationResult && gtaCloudSimulationResult.ok === true),
      reasonCode: reasonCode || 'SANDBOX_UNAVAILABLE',
      localResult: clone(local),
      ...(preflight ? { preflight: clone(preflight) } : {}),
      ...(sandboxResult ? { sandboxResult: clone(sandboxResult) } : {}),
      ...(cloudInspectionResult ? { cloudInspectionResult: clone(cloudInspectionResult) } : {}),
      ...(gtaCloudSimulationResult ? { gtaCloudSimulationResult: clone(gtaCloudSimulationResult) } : {}),
    };
    session.state = 'completed';
    this._emit(session, 'final_verdict', 'completed', `Final verdict: ${finalVerdict.toUpperCase()} (deep static fallback)`, {
      verdict: finalVerdict,
      model,
      fallbackUsed: true,
      sandboxStarted,
      sampleExecutionStarted,
      sandboxCompleted: false,
      pluginDirectExecutionUnsupported: pluginDirectExecutionUnsupported === true,
      cloudInspectionCompleted: !!(cloudInspectionResult && cloudInspectionResult.ok === true),
      gtaCloudSimulationCompleted: !!(gtaCloudSimulationResult && gtaCloudSimulationResult.ok === true),
    });
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

    if (localVerdict === 'malicious') {
      this._emit(session, 'sandbox_decision', 'completed', 'Sandbox skipped: local evidence is already malicious', {
        requested: false,
        localVerdict,
      });
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

    this._emit(session, 'sandbox_decision', 'warning', localVerdict === 'safe'
      ? 'Plus includes isolated behavioral analysis. Send to Sandbox.'
      : 'Suspicious or inconclusive result detected. Send to Sandbox.', {
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
      this._emit(session, 'sandbox_analysis', 'blocked', 'Sandbox execution unavailable; switching to deep static fallback', {
        code,
        sandboxStarted,
        sampleExecutionStarted,
      });
      return this._runDeepStaticFallback(session, {
        model: 'plus',
        reasonCode: code,
        existingLocal: local,
        pluginDirectExecutionUnsupported: GTA_PLUGIN_EXTENSIONS.has(path.extname(session.filePath).toLowerCase()),
        sandboxResult: sandboxResult || { ok: false, verdict: 'inconclusive' },
        sandboxStarted,
        sampleExecutionStarted,
      });
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

  async _runPro(session) {
    this._emit(session, 'preflight', 'running', 'Validating sample before direct Sandbox handoff');
    const preflight = await this.sandbox.preflightSample(session.filePath);
    session.preflight = clone(preflight);
    if (!preflight || preflight.ok !== true) {
      const code = preflight && preflight.code ? preflight.code : 'SANDBOX_PREFLIGHT_FAILED';
      const extension = path.extname(session.filePath).toLowerCase();
      const pluginDirectExecutionUnsupported = code === 'SANDBOX_SAMPLE_TYPE_UNSUPPORTED' && GTA_PLUGIN_EXTENSIONS.has(extension);

      if (pluginDirectExecutionUnsupported) {
        this._emit(session, 'preflight', 'warning', 'GTA plugin cannot be launched directly; switching Pro to non-executing fallback analysis', {
          code,
          extension,
          fallback: 'deep_static_no_execution',
        });
        return this._runDeepStaticFallback(session, {
          model: 'pro',
          reasonCode: code,
          preflight,
          pluginDirectExecutionUnsupported: true,
        });
      }

      this._emit(session, 'preflight', 'blocked', 'Pro Sandbox preflight failed closed', {
        code,
      });
      session.finalResult = {
        model: 'pro',
        verdict: 'inconclusive',
        completionState: 'preflight_failed_closed',
        sandboxRequested: true,
        sandboxStarted: false,
        sampleExecutionStarted: false,
        sandboxCompleted: false,
        preflight: clone(preflight || { ok: false, code: 'SANDBOX_PREFLIGHT_FAILED' }),
      };
      session.state = 'completed';
      this._emit(session, 'final_verdict', 'completed', 'Final verdict: INCONCLUSIVE', {
        verdict: 'inconclusive', model: 'pro', sandboxStarted: false, sampleExecutionStarted: false, sandboxCompleted: false,
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
      this._emit(session, 'sandbox_analysis', 'blocked', 'Direct Sandbox unavailable; switching Pro to deep static fallback', {
        code,
        sandboxStarted,
        sampleExecutionStarted,
      });
      return this._runDeepStaticFallback(session, {
        model: 'pro',
        reasonCode: code,
        preflight,
        pluginDirectExecutionUnsupported: GTA_PLUGIN_EXTENSIONS.has(path.extname(session.filePath).toLowerCase()),
        sandboxResult: sandboxResult || { ok: false, verdict: 'inconclusive' },
        sandboxStarted,
        sampleExecutionStarted,
      });
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
      preflight: clone(preflight),
      sandboxResult: clone(sandboxResult),
    };
    session.state = 'completed';
    this._emit(session, 'final_verdict', 'completed', `Final verdict: ${finalVerdict.toUpperCase()}`, {
      verdict: finalVerdict, model: 'pro', sandboxStarted: true, sampleExecutionStarted: true, sandboxCompleted: true,
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
  deepStaticFallbackVerdict,
  GTA_PLUGIN_EXTENSIONS,
};
