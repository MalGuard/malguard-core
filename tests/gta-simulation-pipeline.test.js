'use strict';

const assert = require('assert');
const { ModelScanPipelineManager } = require('../desktop-app/pro-scan-pipeline.js');
const { GtaSimulationEngine } = require('../desktop-app/gta-simulation/simulation-engine.js');
const { AiEvidenceBridge } = require('../desktop-app/gta-simulation/ai-evidence-bridge.js');

async function waitFor(manager, id) {
  for (let i = 0; i < 100; i++) {
    const session = manager.snapshot(id);
    if (session && (session.state === 'completed' || session.state === 'failed')) return session;
    await new Promise(resolve => setTimeout(resolve, 5));
  }
  throw new Error('pipeline did not finish');
}

function baseScanner(verdict) {
  return {
    scanPath: async (_file, mode) => ({
      finalVerdict: verdict,
      mode,
      contentSha256: 'a'.repeat(64),
      detectorResult: { modType: 'plugin', route: 'ENGINE', confidence: 'high', suspiciousPackaging: false },
      threatIntel: { status: 'disabled' },
    }),
  };
}

function sandbox({ unsupportedPlugin = false } = {}) {
  return {
    preflightSample: async file => unsupportedPlugin
      ? { ok: false, code: 'SANDBOX_SAMPLE_TYPE_UNSUPPORTED', extension: '.asi' }
      : { ok: true, path: file, sha256: 'b'.repeat(64), size: 10, extension: '.exe' },
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
  const gtaSimulation = new GtaSimulationEngine();
  const aiEvidence = new AiEvidenceBridge();

  const standardManager = new ModelScanPipelineManager({
    scanner: baseScanner('safe'),
    sandbox: sandbox(),
    gtaSimulation,
    aiEvidence,
  });
  const standard = await waitFor(standardManager, standardManager.start('/tmp/test.asi', 'standard').id);
  assert.equal(standard.finalResult.verdict, 'safe', 'simulation must not rewrite Standard verdict');
  assert.equal(standard.finalResult.gtaSimulation.ok, true);
  assert.equal(standard.finalResult.gtaSimulation.model, 'standard');
  assert.equal(standard.finalResult.gtaSimulation.verdictPolicy.canPromoteSafe, false);
  assert.equal(standard.finalResult.aiEvidence.available, false);
  assert(standard.events.some(event => event.phase === 'gta_simulation' && event.status === 'completed'));

  const plusManager = new ModelScanPipelineManager({
    scanner: baseScanner('malicious'),
    sandbox: sandbox(),
    gtaSimulation,
    aiEvidence,
  });
  const plus = await waitFor(plusManager, plusManager.start('/tmp/test.dll', 'plus').id);
  assert.equal(plus.finalResult.verdict, 'malicious');
  assert.equal(plus.finalResult.gtaSimulation.model, 'plus');
  assert.equal(plus.finalResult.gtaSimulation.remediationPlan.hostMutationAllowed, false);
  assert.equal(plus.finalResult.aiEvidence.onlineLearning, false);

  const proManager = new ModelScanPipelineManager({
    scanner: baseScanner('safe'),
    sandbox: sandbox({ unsupportedPlugin: true }),
    gtaSimulation,
    aiEvidence,
  });
  const pro = await waitFor(proManager, proManager.start('/tmp/test.asi', 'pro').id);
  assert.equal(pro.finalResult.verdict, 'inconclusive', 'non-executing Pro plugin fallback must remain fail-closed');
  assert.equal(pro.finalResult.pluginDirectExecutionUnsupported, true);
  assert.equal(pro.finalResult.gtaSimulation.model, 'pro');
  assert.equal(pro.finalResult.gtaSimulation.sampleProfile.directExecutionAttempted, false);
  assert.equal(pro.finalResult.aiEvidence.available, false);

  console.log('✓ GTA Simulation integration: Standard, Plus and Pro all receive synthetic context without changing verdict safety PASS');
})().catch(error => {
  console.error(error.stack || error);
  process.exit(1);
});
