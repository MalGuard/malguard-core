'use strict';

const assert = require('assert');
const {
  FUSION_ENGINE_VERSION,
  localStaticCoverage,
  fuseEvidence,
} = require('../desktop-app/fusion/evidence-fusion-engine.js');

function safePe() {
  return {
    finalVerdict: 'safe',
    sourceIdentity: { sha256: 'a'.repeat(64), revalidated: true },
    engineResult: { rulesStatus: 'official', peValid: true },
    threatIntel: { status: 'hash_not_found', source: 'cache' },
  };
}

assert.equal(typeof FUSION_ENGINE_VERSION, 'string');

const coverage = localStaticCoverage(safePe());
assert.equal(coverage.fullCoverage, true);
assert.equal(coverage.primaryAnalyzersCompleted, 1);

const safe = fuseEvidence({ localResult: safePe(), model: 'pro' });
assert.equal(safe.verdict, 'safe');
assert.equal(safe.basis, 'full_static_fusion_coverage');
assert.equal(safe.layers.behavioral.proven, false);
assert.equal(safe.layers.ai.advisoryOnly, true);
assert(safe.riskScore < 20);

const noAnalyzer = fuseEvidence({
  localResult: {
    finalVerdict: 'safe',
    sourceIdentity: { sha256: 'b'.repeat(64), revalidated: true },
    threatIntel: { status: 'disabled' },
  },
});
assert.equal(noAnalyzer.verdict, 'inconclusive');
assert(noAnalyzer.coverage.issues.includes('no_primary_static_analyzer_completed'));

const staleIdentity = safePe();
staleIdentity.sourceIdentity.revalidated = false;
assert.equal(fuseEvidence({ localResult: staleIdentity }).verdict, 'inconclusive');

const knownBad = safePe();
knownBad.threatIntel = { status: 'known_malicious', signature: 'Synthetic.Test' };
assert.equal(fuseEvidence({ localResult: knownBad }).verdict, 'malicious');

const fakeSandbox = fuseEvidence({
  localResult: { finalVerdict: 'inconclusive' },
  sandboxResult: { ok: true, sandboxLaunched: true, sampleExecutionStarted: false, verdict: 'safe', releaseGrade: true },
});
assert.equal(fakeSandbox.verdict, 'inconclusive');

const provenBad = fuseEvidence({
  localResult: safePe(),
  sandboxResult: { ok: true, sandboxLaunched: true, sampleExecutionStarted: true, verdict: 'malicious', releaseGrade: true },
});
assert.equal(provenBad.verdict, 'malicious');

const aiCannotInventSafe = fuseEvidence({
  localResult: { finalVerdict: 'inconclusive' },
  aiEvidenceResult: { ok: true, status: 'completed', risk: 'low', summary: 'SAFE' },
});
assert.equal(aiCannotInventSafe.verdict, 'inconclusive');
assert.equal(aiCannotInventSafe.layers.ai.canPromoteSafe, false);

console.log('✓ THS Stage 1: Fusion Engine deterministic unit and SAFE coverage gate PASS');
