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
assert.match(js, /Pro: direct Sandbox analysis/);
assert.match(js, /Plus: deep staged analysis/);
assert.match(js, /local runtime self-certification/);
assert.match(js, /real Windows Sandbox self-test/);
assert.doesNotMatch(js, /\/api\/sandbox\/analyze/, 'direct sample analysis should be reached through Pro model, not a duplicate UI control');

assert.match(html, /100% Product Validation & Runtime Sandbox Self-Certification/);
assert.match(html, /id="finalSandboxTest"/);
assert.match(html, /id="finalSandboxSummary"/);
assert.match(html, /release artifact can reach 100% engineering and product readiness/);
assert.match(html, /behavioral execution remains fail-closed/);
assert.match(html, /missing WindowsSandbox\.exe on the CI runner therefore does not make the product incomplete/);
assert.match(js, /\/api\/sandbox\/readiness/);
assert.match(js, /productReleaseReady===true/);
assert.match(js, /productReadinessPercent/);
assert.match(js, /runtimeCapabilitiesReadyOnCurrentHost/);
assert.match(js, /runtimeSelfCertification/);
assert.match(js, /PRODUCT READINESS 100%/);
assert.match(js, /Sandbox-dependent runtime paths remain safely LOCKED/);
assert.match(js, /current host has not certified Windows Sandbox/);

console.log('✓ Choose Model UI: product readiness can reach 100% while host-specific Sandbox execution remains visibly fail-closed until local certification');
