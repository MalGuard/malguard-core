'use strict';

// This gate verifies the current product contract. It does not invent a percentage
// of product readiness or substitute synthetic tests for Windows installation proof.
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { UnifiedScanPipeline, unifiedResult } = require('../desktop-app/unified-scan-pipeline');
const server = require('../desktop-app/server');

try {
  assert(server.modelPipeline instanceof UnifiedScanPipeline);
  assert.equal(server.sandbox, undefined);
  assert.equal(server.cloudInspection, undefined);
  for (const status of ['not_found', 'unavailable', 'not_configured', 'auth_error']) {
    assert.equal(unifiedResult({ finalVerdict:'safe', threatIntel:{status} }).verdict, 'inconclusive');
  }
  assert.equal(unifiedResult({ finalVerdict:'malicious' }).verdict, 'malicious');
  const html = fs.readFileSync(path.join(__dirname, '../desktop-app/public/index.html'), 'utf8');
  assert(!/id="(?:scanModel|cloudFallback|finalSandboxTest)"/.test(html));
  console.log(JSON.stringify({
    ok:true, scope:'unified_static_product_contract', executionMode:'static_only',
    dynamicAnalysis:'disabled', externalFileUpload:false, unknownIsSafe:false,
    productReleaseReady:false,
    releaseValidation:'requires_separate_windows_build_install_runtime_and_signing_evidence',
    safety:{untrustedSamplesExecuted:false, malwareDownloaded:false},
  }, null, 2));
} catch (error) {
  console.error('PRODUCT_READINESS_GATE_FAILED: '+error.message);
  process.exitCode=1;
}
