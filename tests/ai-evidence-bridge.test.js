'use strict';

const assert = require('assert');
const {
  AiEvidenceBridge,
  AI_EVIDENCE_SCHEMA_VERSION,
} = require('../desktop-app/gta-simulation/ai-evidence-bridge.js');

(async () => {
  const empty = new AiEvidenceBridge();
  const caps = empty.capabilities();
  assert.equal(caps.schemaVersion, AI_EVIDENCE_SCHEMA_VERSION);
  assert.equal(caps.available, false);
  assert.equal(caps.onlineLearning, false);
  assert.equal(caps.modelWeightsMutableDuringScan, false);
  assert.equal(caps.autoRemediation, false);

  const unavailable = await empty.analyze({
    model: 'standard',
    simulation: { ok: true },
    localResult: { finalVerdict: 'safe' },
  });
  assert.equal(unavailable.ok, true);
  assert.equal(unavailable.available, false);
  assert.equal(unavailable.status, 'provider_not_configured');
  assert.equal(unavailable.onlineLearning, false);
  assert.equal(unavailable.modelWeightsMutableDuringScan, false);
  assert.equal(unavailable.autoRemediation, false);

  let seen = null;
  const bridge = new AiEvidenceBridge({
    provider: {
      name: 'test-provider',
      async analyzeEvidence(evidence) {
        seen = evidence;
        return {
          risk: 'high',
          summary: 'Bounded defensive assessment',
          recommendedActions: ['quarantine_sample', 'delete_host_files', 'review_evidence', 'quarantine_sample'],
        };
      },
    },
  });

  const result = await bridge.analyze({
    model: 'pro',
    simulation: { ok: true, verdictPolicy: { canPromoteSafe: false } },
    localResult: {
      finalVerdict: 'suspicious',
      hardeningError: null,
      threatIntel: { status: 'known_malicious', source: 'cache', signature: 'Unit.Test', fileType: 'dll', tags: ['test'] },
      detectorResult: { modType: 'plugin', route: 'ENGINE', confidence: 'high', suspiciousPackaging: false },
      engineResult: {
        verdict: 'suspicious', score: 55, confidence: 'high', rulesStatus: 'official', peValid: true,
        riskFloorApplied: 'suspicious', gtaContextDetected: true,
        evidence: [{ rule:'IMP-1', category:'process_injection', severity:'high', confidence:'high', weight:20 }],
        peSummary: { is64:true, numberOfSections:5, isDllFlagSet:true, namedImportCount:10, ordinalImportCount:0, tls:{present:false}, overlay:{present:false,size:0}, security:{present:true} },
      },
      multiLayer: { finalVerdict:'suspicious', decision:{primaryReason:'rule_evidence'}, conflict:{detected:false}, gates:[{gate:'rule_evidence',result:'SUSPICIOUS'}] },
    },
  });

  assert.equal(result.ok, true);
  assert.equal(result.available, true);
  assert.equal(result.status, 'completed');
  assert.equal(result.provider, 'test-provider');
  assert.equal(result.risk, 'high');
  assert.deepEqual(result.recommendedActions.sort(), ['quarantine_sample', 'review_evidence'].sort());
  assert.equal(result.onlineLearning, false);
  assert.equal(result.modelWeightsMutableDuringScan, false);
  assert.equal(result.autoRemediation, false);
  assert.equal(seen.schemaVersion, AI_EVIDENCE_SCHEMA_VERSION);
  assert.equal(seen.model, 'pro');
  assert.equal(seen.scanner.threatIntel.status, 'known_malicious');
  assert.equal(seen.scanner.detector.modType, 'plugin');
  assert.equal(seen.scanner.engine.score, 55);
  assert.equal(seen.scanner.engine.evidence[0].category, 'process_injection');
  assert.equal(seen.scanner.engine.pe.numberOfSections, 5);
  assert.equal(seen.scanner.multiLayer.gates[0].result, 'SUSPICIOUS');
  assert(!JSON.stringify(seen).includes('contentSha256'));
  assert(!JSON.stringify(seen).includes('path'));

  console.log('✓ AI evidence bridge: provider boundary, action allowlist, no online learning and no auto-remediation PASS');
})().catch(error => {
  console.error(error.stack || error);
  process.exit(1);
});
