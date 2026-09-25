'use strict';

const assert = require('assert');
const {
  MalGuardCloudAiProvider,
  DEFAULT_ENDPOINT,
  MODEL_MAP,
  compactEvidence,
  parseJsonAnswer,
} = require('../desktop-app/gta-simulation/malguard-cloud-ai-provider.js');

(async () => {
  assert.match(DEFAULT_ENDPOINT, /^https:\/\//);
  assert.equal(MODEL_MAP.standard, 'fast');
  assert.equal(MODEL_MAP.plus, 'auto');
  assert.equal(MODEL_MAP.pro, 'strong');

  const compact = compactEvidence({
    model: 'pro',
    scanner: {
      finalVerdict: 'suspicious',
      hardeningError: null,
      threatIntelStatus: 'unavailable',
      contentSha256: 'f'.repeat(64),
      path: 'C:\\Secret\\menu.asi',
    },
    simulation: {
      local: {
        depth: 'synthetic-runtime-model-plus-remediation',
        sampleProfile: {
          extension: '.asi',
          modType: 'plugin',
          gtaPluginCandidate: true,
          directExecutionAttempted: false,
        },
        evidence: {
          scannerVerdict: 'suspicious',
          signals: ['scanner_suspicious'],
          contentSha256: 'f'.repeat(64),
        },
      },
      isolated: {
        ok: true,
        mode: 'cloud_gta_simulation',
        sampleExecutionAttempted: false,
        sampleExecutionStarted: false,
        report: { treeReady: true, sha256: 'f'.repeat(64) },
        isolation: { networkPolicy: 'deny-all', destroyAfterRun: true },
      },
    },
  });

  const compactJson = JSON.stringify(compact);
  assert(!compactJson.includes('C:\\Secret'), 'full paths must not enter AI evidence');
  assert(!compactJson.includes('f'.repeat(64)), 'SHA-256 must not enter AI evidence');
  assert(!Object.prototype.hasOwnProperty.call(compact.scanner, 'contentSha256'));
  assert.equal(compact.gtaSimulation.extension, '.asi');
  assert.equal(compact.isolatedSimulation.destroyAfterRun, true);

  assert.deepEqual(
    parseJsonAnswer('{"risk":"low","summary":"ok","recommendedActions":["review_evidence"]}'),
    { risk:'low', summary:'ok', recommendedActions:['review_evidence'] }
  );
  assert.deepEqual(
    parseJsonAnswer('```json\n{"risk":"medium","summary":"review","recommendedActions":[]}\n```'),
    { risk:'medium', summary:'review', recommendedActions:[] }
  );

  let request = null;
  const provider = new MalGuardCloudAiProvider({
    endpoint: 'https://ai.example.test/api/chat',
    fetchImpl: async (url, options) => {
      request = { url, options, body: JSON.parse(options.body) };
      return {
        ok: true,
        status: 200,
        json: async () => ({
          model: 'strong',
          text: '{"risk":"high","summary":"Keep the plugin blocked pending verified runtime evidence.","recommendedActions":["keep_blocked","review_evidence"]}',
        }),
      };
    },
  });

  assert.equal(provider.available(), true);
  const result = await provider.analyzeEvidence({
    model: 'pro',
    scanner: {
      finalVerdict: 'suspicious',
      hardeningError: null,
      threatIntelStatus: 'unavailable',
    },
    simulation: {
      local: {
        depth: 'synthetic-runtime-model-plus-remediation',
        sampleProfile: { extension: '.asi', modType: 'plugin', gtaPluginCandidate: true, directExecutionAttempted: false },
        evidence: { scannerVerdict: 'suspicious', signals: ['scanner_suspicious'] },
      },
      isolated: {
        ok: true,
        mode: 'cloud_gta_simulation',
        sampleExecutionAttempted: false,
        sampleExecutionStarted: false,
        report: { treeReady: true },
        isolation: { networkPolicy: 'deny-all', destroyAfterRun: true },
      },
    },
  });

  assert.equal(result.risk, 'high');
  assert.deepEqual(result.recommendedActions, ['keep_blocked','review_evidence']);
  assert.equal(request.url, 'https://ai.example.test/api/chat');
  assert.equal(request.body.model, 'strong');
  assert.equal(request.body.messages.length, 1);
  const prompt = request.body.messages[0].text;
  assert(prompt.includes('No raw file bytes are provided'));
  assert(prompt.includes('Do not claim a file is safe'));
  assert(!prompt.includes('C:\\Secret'));
  assert(!/[a-f0-9]{64}/.test(prompt), 'AI prompt must not contain SHA-256');
  assert.equal(request.body.clientContext.privacy, 'bounded-metadata-no-file-bytes');

  console.log('✓ MalGuard AI provider: real chat endpoint contract, model mapping, bounded metadata privacy and defensive JSON output PASS');
})().catch(error => {
  console.error(error.stack || error);
  process.exit(1);
});
