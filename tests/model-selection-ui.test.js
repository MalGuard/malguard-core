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
assert.doesNotMatch(js, /\/api\/sandbox\/analyze/, 'direct sample analysis should be reached through Pro model, not a duplicate UI control');

assert.match(html, /Virtual Windows Validation Lab & Final Sandbox Acceptance/);
assert.match(html, /id="finalSandboxTest"/);
assert.match(html, /id="finalSandboxSummary"/);
assert.match(html, /100% engineering validation without pretending that WindowsSandbox\.exe ran/);
assert.match(html, /Real Windows Sandbox remains a separate Pro behavioral runtime certification gate/);
assert.match(js, /\/api\/sandbox\/readiness/);
assert.match(js, /report\.releaseReady===true/);
assert.match(js, /engineeringValidationPercent/);
assert.match(js, /virtualWindowsLab/);
assert.match(js, /ENGINEERING VALIDATION 100%/);
assert.match(js, /runtime certification remains pending and is not being faked/);
assert.match(js, /No full-release certification has been claimed/);

console.log('✓ Choose Model UI: Standard/Plus/Pro semantics plus 100% engineering/virtual-Windows validation surface passed');
