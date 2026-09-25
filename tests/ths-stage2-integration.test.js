'use strict';

const assert = require('assert');
const { ModelScanPipelineManager } = require('../desktop-app/pro-scan-pipeline.js');

async function waitFor(manager, id) {
  for (let i = 0; i < 200; i++) {
    const s = manager.snapshot(id);
    if (s && (s.state === 'completed' || s.state === 'failed')) return s;
    await new Promise(resolve => setTimeout(resolve, 2));
  }
  throw new Error('THS Stage 2 timeout');
}

function unavailableSandbox({ unsupported = false } = {}) {
  return {
    preflightSample: async file => unsupported
      ? { ok: false, code: 'SANDBOX_SAMPLE_TYPE_UNSUPPORTED', extension: '.asi' }
      : { ok: true, path: file, sha256: 'f'.repeat(64), size: 32, extension: '.exe' },
    analyzeUntrustedSample: async () => ({
      ok: false,
      verdict: 'inconclusive',
      code: 'NO_ISOLATION_BACKEND_AVAILABLE',
      sandboxLaunched: false,
      sampleExecutionStarted: false,
    }),
  };
}

(async () => {
  const safePeScanner = {
    scanPath: async () => ({
      finalVerdict: 'safe',
      contentSha256: 'a'.repeat(64),
      sourceIdentity: { sha256: 'a'.repeat(64), revalidated: true },
      engineResult: { rulesStatus: 'official', peValid: true },
      threatIntel: { status: 'hash_not_found', source: 'cache' },
    }),
  };

  const pro = new ModelScanPipelineManager({
    scanner: safePeScanner,
    sandbox: unavailableSandbox({ unsupported: true }),
  });
  const proSession = await waitFor(pro, pro.start('/tmp/ths-safe.asi', 'pro', { allowAiEvidence: false }).id);
  assert.equal(proSession.finalResult.fallbackUsed, true);
  assert.equal(proSession.finalResult.dynamicAnalysisUnavailable, true);
  assert.equal(proSession.finalResult.sampleExecutionStarted, false);
  assert.equal(proSession.finalResult.verdict, 'safe');
  assert.equal(proSession.finalResult.fusion.basis, 'full_static_fusion_coverage');
  assert.equal(proSession.finalResult.fusion.safeClaim.absoluteGuarantee, false);

  const plus = new ModelScanPipelineManager({
    scanner: {
      scanPath: async () => ({
        finalVerdict: 'safe',
        contentSha256: 'b'.repeat(64),
        sourceIdentity: { sha256: 'b'.repeat(64), revalidated: true },
        scriptAnalysis: { supported: true, errorCode: null, finalVerdict: 'safe' },
        threatIntel: { status: 'unavailable' },
      }),
    },
    sandbox: unavailableSandbox(),
  });
  const plusSession = await waitFor(plus, plus.start('/tmp/ths-safe.lua', 'plus', { allowAiEvidence: false }).id);
  assert.equal(plusSession.finalResult.fallbackUsed, true);
  assert.equal(plusSession.finalResult.verdict, 'safe');
  assert.equal(plusSession.finalResult.fusion.coverage.primaryAnalyzersCompleted, 1);

  const degraded = new ModelScanPipelineManager({
    scanner: {
      scanPath: async () => ({
        finalVerdict: 'safe',
        sourceIdentity: { sha256: 'c'.repeat(64), revalidated: false },
        engineResult: { rulesStatus: 'official', peValid: true },
      }),
    },
    sandbox: unavailableSandbox({ unsupported: true }),
  });
  const degradedSession = await waitFor(degraded, degraded.start('/tmp/ths-degraded.asi', 'pro', { allowAiEvidence: false }).id);
  assert.equal(degradedSession.finalResult.verdict, 'inconclusive');
  assert(degradedSession.finalResult.fusion.coverage.issues.includes('source_identity_not_revalidated'));

  console.log('✓ THS Stage 2: pipeline integration, Sandbox outage fallback, ASI/Lua routing PASS');
})().catch(error => {
  console.error(error.stack || error);
  process.exit(1);
});
