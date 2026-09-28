'use strict';

const crypto = require('crypto');
const path = require('path');
const { fuseEvidence } = require('./fusion/evidence-fusion-engine.js');

// Legacy names are accepted only as aliases. Every request receives the same analysis.
const ALIASES = new Set(['unified', 'standard', 'plus', 'pro']);
const TERMINAL = new Set(['completed', 'failed', 'cancelled']);
const clone = value => JSON.parse(JSON.stringify(value));

function unifiedResult(localResult) {
  const fusion = fuseEvidence({ localResult, model: 'pro' });
  const noDetection = fusion.verdict === 'safe';
  // An absence of detections (including a reputation miss) is never approval.
  const verdict = noDetection ? 'inconclusive' : fusion.verdict;
  fusion.verdict = verdict;
  fusion.model = 'unified';
  fusion.safeClaim = { allowed: false, bounded: true, absoluteGuarantee: false, basis: null };
  if (noDetection) {
    fusion.basis = 'no_static_detection_not_proof_of_safety';
    fusion.confidence = 'low';
    fusion.riskScore = 50;
  }
  return {
    model: 'unified', verdict,
    completionState: localResult && localResult.hardeningError ? 'failed_closed' : 'complete_with_coverage_limits',
    executionMode: 'static_only', sampleExecutionStarted: false, sandboxRequested: false,
    sandboxStarted: false, fileBytesShared: false,
    dynamicAnalysis: { status: 'not_performed', reason: 'disabled_by_product_design' },
    limitations: [...new Set([...fusion.limitations, 'static_analysis_cannot_prove_safety', 'no_dynamic_analysis'])],
    fusion, localResult,
  };
}

class UnifiedScanPipeline {
  constructor({ scanner, now = () => Date.now(), ttlMs = 600000, maxSessions = 32, maxActive = 4 } = {}) {
    if (!scanner || typeof scanner.scanPath !== 'function') throw new TypeError('scanner.scanPath is required');
    this.scanner = scanner;
    this.now = now;
    this.ttlMs = ttlMs;
    this.maxSessions = maxSessions;
    this.maxActive = maxActive;
    this.sessions = new Map();
  }

  _prune() {
    for (const [id, s] of this.sessions) {
      if (TERMINAL.has(s.state) && this.now() - s.updatedAt > this.ttlMs) this.sessions.delete(id);
    }
    for (const [id, s] of this.sessions) {
      if (this.sessions.size < this.maxSessions) break;
      if (TERMINAL.has(s.state)) this.sessions.delete(id);
    }
  }

  start(filePath, model = 'unified', { onFinish = null } = {}) {
    if (typeof filePath !== 'string' || !filePath.trim()) throw Object.assign(new Error('scan path required'), { code: 'PATH_REQUIRED' });
    if (!ALIASES.has(model)) throw Object.assign(new Error('unknown scan model'), { code: 'INVALID_MODEL' });
    this._prune();
    const active = [...this.sessions.values()].filter(s => !TERMINAL.has(s.state)).length;
    if (active >= this.maxActive || this.sessions.size >= this.maxSessions) {
      throw Object.assign(new Error('scan capacity reached'), { code: 'TOO_MANY_LOCAL_SCANS' });
    }
    const s = { id: crypto.randomUUID(), model: 'unified', pipelineVersion: '2.0.0', state: 'queued',
      createdAt: this.now(), updatedAt: this.now(), events: [], localResult: null, finalResult: null, error: null,
      controller: new AbortController(), filePath: path.resolve(filePath) };
    this.sessions.set(s.id, s);
    this._emit(s, 'prepare', 'queued', 'Preparing local non-executing analysis');
    void this._run(s, onFinish);
    return this.snapshot(s.id);
  }

  _emit(s, phase, status, message) {
    s.events.push({ seq: s.events.length + 1, phase, status, message });
    s.updatedAt = this.now();
  }

  snapshot(id) {
    const s = this.sessions.get(String(id || ''));
    if (!s) return null;
    const { controller, filePath, ...visible } = s;
    return clone(visible);
  }

  cancel(id) {
    const s = this.sessions.get(String(id || ''));
    if (!s) return null;
    if (!TERMINAL.has(s.state) && !s.controller.signal.aborted) {
      s.controller.abort();
      s.state = 'cancelling';
      this._emit(s, 'cancel', 'running', 'Stopping analysis; waiting for active reads and cleanup');
    }
    return this.snapshot(id);
  }

  async _run(s, onFinish) {
    let state = 'completed';
    try {
      // Let start() return its stable queued snapshot before work begins.
      await Promise.resolve();
      s.controller.signal.throwIfAborted();
      s.state = 'running';
      this._emit(s, 'static_scan', 'running', 'Running local static engines and SHA-256 reputation lookup');
      const local = await this.scanner.scanPath(s.filePath, 'pro', { signal: s.controller.signal });
      s.controller.signal.throwIfAborted();
      s.localResult = clone(local);
      s.finalResult = unifiedResult(local);
      if (local.hardeningError) {
        state = 'failed';
        s.error = { code: local.hardeningError, message: 'File analysis could not finish reliably.' };
      }
      this._emit(s, 'static_scan', state === 'failed' ? 'failed' : 'completed', 'Static analysis finished; no sample execution performed');
    } catch (error) {
      state = s.controller.signal.aborted ? 'cancelled' : 'failed';
      // Do not expose provider exception messages, paths or credentials to the UI.
      s.error = { code: state === 'cancelled' ? 'SCAN_CANCELLED' : 'SCAN_FAILED', message: 'No complete scan result is available.' };
      s.finalResult = unifiedResult(null);
      s.finalResult.completionState = state === 'cancelled' ? 'cancelled' : 'failed_closed';
    } finally {
      s.state = 'finishing';
      try { if (onFinish) await onFinish(); }
      catch (_) {
        state = 'failed';
        s.error = { code: 'SCAN_CLEANUP_FAILED', message: 'Temporary scan copy cleanup failed.' };
        s.finalResult = unifiedResult(null);
        s.finalResult.completionState = 'failed_closed';
      }
      // Cancellation can arrive during cleanup; never publish a completed verdict after it.
      if (s.controller.signal.aborted && state !== 'failed') {
        state = 'cancelled';
        s.error = { code: 'SCAN_CANCELLED', message: 'Scan cancelled.' };
        s.finalResult = unifiedResult(null);
        s.finalResult.completionState = 'cancelled';
      }
      s.state = state;
      this._emit(s, 'final_verdict', state === 'completed' ? 'completed' : 'failed', state === 'completed' ? 'Analysis result ready with limitations' : 'Analysis stopped without approval');
    }
  }
}
module.exports = { UnifiedScanPipeline, unifiedResult, ALIASES };
