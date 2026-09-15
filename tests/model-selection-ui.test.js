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

assert.match(html, /Isolation Readiness & Final Windows Sandbox Acceptance/);
assert.match(html, /id="finalSandboxTest"/);
assert.match(html, /id="finalSandboxSummary"/);
assert.match(html, /MXC synthetic evidence never unlocks Pro behavioral execution by itself/);
assert.match(js, /\/api\/sandbox\/readiness/);
assert.match(js, /report\.releaseReady===true/);
assert.match(js, /mxc\.validated===true/);
assert.match(js, /Pro behavioral release remains pending/);
assert.match(js, /No full-release certification has been claimed|No full-release certification/);

console.log('✓ Choose Model UI: Standard/Plus/Pro semantics and scoped in-app isolation readiness surface passed');
