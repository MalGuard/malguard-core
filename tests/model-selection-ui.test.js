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
assert.match(js, /Plus: deep local analysis, verified local Sandbox execution/);
assert.match(js, /Pro: direct verified local behavioral analysis/);
assert.doesNotMatch(js, /\/api\/sandbox\/analyze/, 'direct sample analysis should be reached through Pro model, not a duplicate UI control');

assert.match(html, /Security Health/);
assert.match(html, /Hybrid Isolation/);
assert.match(html, /id="finalSandboxTest"/);
assert.match(html, /id="finalSandboxSummary"/);
assert.match(html, /id="modelDiagnostics"/);
assert.match(html, /Advanced diagnostics/);
assert.match(html, /disposable Cloud Inspection/);

assert.match(js, /Secure Sandbox setup required/);
assert.match(js, /The file was not executed outside the Sandbox/);
assert.match(js, /Check Sandbox compatibility/);
assert.match(js, /Run Standard scan instead/);
assert.match(js, /Premium Sandbox execution remains safely disabled until the check succeeds/);
assert.match(html, /id="cloudFallback"/);
assert.match(html, /destroyed after the job/);
assert.match(js, /cloud_ephemeral_inspection/);
assert.match(js, /cloudFallback:/);
assert.match(js, /\/api\/sandbox\/readiness/);
assert.match(js, /runtimeCapabilitiesReadyOnCurrentHost===true/);
assert.match(js, /sandbox_unavailable_fail_closed/);
assert.doesNotMatch(js, /FAIL — validation request could not complete/);
assert.doesNotMatch(js, /PRODUCT READINESS 100%/);
assert.doesNotMatch(js, /HARDENED_SANDBOX_ACCEPTANCE_PENDING/);

console.log('✓ Premium Sandbox UX: Plus/Pro remain fail-closed while customer-facing UI shows protected/setup states and keeps technical codes in advanced diagnostics');
