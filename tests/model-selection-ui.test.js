'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const html = fs.readFileSync(path.join(__dirname, '..', 'desktop-app', 'public', 'index.html'), 'utf8');
const js = fs.readFileSync(path.join(__dirname, '..', 'desktop-app', 'public', 'app.js'), 'utf8');

assert.match(html, /id="scanModel"/);
assert.match(html, /<option value="standard">Standard<\/option>/);
assert.match(html, /<option value="plus">Plus<\/option>/);
assert.match(html, /<option value="pro">Pro<\/option>/);
assert.doesNotMatch(html, /data-scan-mode=/, 'old mode buttons must not remain');
assert.match(js, /\/api\/model-scan\/start/);
assert.match(js, /Plus: deep local analysis \+ synthetic GTA context/);
assert.match(js, /Pro: verified local behavioral analysis when possible/);
assert.doesNotMatch(js, /\/api\/sandbox\/analyze/, 'direct sample analysis should be reached through Pro model, not a duplicate UI control');

assert.match(html, /Security Health/);
assert.match(html, /Hybrid Isolation/);
assert.match(html, /id="finalSandboxTest"/);
assert.match(html, /id="finalSandboxSummary"/);
assert.match(html, /id="modelDiagnostics"/);
assert.match(html, /Advanced diagnostics/);
assert.match(html, /disposable GTA Cloud Simulation/);

assert.match(js, /Secure Sandbox setup required/);
assert.match(js, /The file was not executed outside the Sandbox/);
assert.match(js, /Check Sandbox compatibility/);
assert.match(js, /Run Standard scan instead/);
assert.match(js, /Premium Sandbox execution remains safely disabled until the check succeeds/);
assert.match(html, /id="cloudFallback"/);
assert.match(html, /id="aiEvidence"/);
assert.match(html, /bounded scan metadata/);
assert.match(html, /File bytes, filename, full path and SHA-256 are not sent/);
assert.match(html, /destroyed after the job/);
assert.match(js, /gta_cloud_simulation/);
assert.match(js, /ai_evidence/);
assert.match(js, /aiEvidence:/);
assert.match(js, /cloudFallback:/);
assert.match(js, /\/api\/sandbox\/readiness/);
assert.match(js, /runtimeCapabilitiesReadyOnCurrentHost===true/);
assert.match(js, /sandbox_unavailable_fail_closed/);
assert.doesNotMatch(js, /FAIL — validation request could not complete/);
assert.doesNotMatch(js, /PRODUCT READINESS 100%/);
assert.doesNotMatch(js, /HARDENED_SANDBOX_ACCEPTANCE_PENDING/);

console.log('✓ GTA Guard 0.8 UX: all models show GTA simulation, opt-in metadata-only AI and fail-closed security states');
