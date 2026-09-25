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
    localResult: { finalVerdict: 'suspicious', hardeningError: null, threatIntel: { status: 'unavailable' } },
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

  console.log('✓ AI evidence bridge: provider boundary, action allowlist, no online learning and no auto-remediation PASS');
})().catch(error => {
  console.error(error.stack || error);
  process.exit(1);
});
