'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const root = path.resolve(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'desktop-app/public/index.html'), 'utf8');
const js = fs.readFileSync(path.join(root, 'desktop-app/public/app.js'), 'utf8');
const css = fs.readFileSync(path.join(root, 'desktop-app/public/styles.css'), 'utf8');
const chooser = html.indexOf('id="scanFile"');
const feedback = html.indexOf('id="scanOut"');
const advanced = html.indexOf('Advanced: enter a full file path');
const flow = html.indexOf('id="modelFlow"');
assert(chooser < feedback && feedback < advanced && feedback < flow, 'scan feedback must be next to the file picker');
assert(html.indexOf('id="modelDiagnostics"') < flow, 'Standard scan diagnostics must be visible outside the optional model flow');
assert(css.includes('.scan-summary.result-error') && css.includes('border:2px solid #f87171'), 'failure needs a distinct red appearance');

function element(id) {
  return {
    id, value: '', files: [], hidden: false, disabled: false, className: '', textContent: '', children: [],
    setAttribute(name, value) { this[name] = value; },
    replaceChildren() { this.children = []; this.textContent = ''; },
    append(...nodes) { this.children.push(...nodes); this.textContent += nodes.map(n => n.textContent || '').join(''); },
  };
}

(async () => {
  const ids = new Map();
  const get = id => { if (!ids.has(id)) ids.set(id, element(id)); return ids.get(id); };
  const requests = [];
  const document = {
    getElementById: get,
    querySelectorAll: () => [],
    createElement: tag => element(tag),
    createTextNode: text => ({ textContent: text }),
  };
  const fetch = async url => {
    requests.push(String(url));
    if (String(url).startsWith('/api/model-scan/upload')) throw new Error('synthetic_network_failure');
    return { ok: true, json: async () => ({ settings: {}, entitlement: {}, supportedModels: [] }) };
  };
  vm.runInNewContext(js, { document, fetch, setTimeout, console });
  get('scanModel').value = 'standard';

  get('scanFile').files = [{ name: 'notes.pdf', size: 514 }];
  await get('scanBtn').onclick();
  assert.equal(get('scanOut').className, 'scan-summary result-unsupported');
  assert(!requests.some(url => url.startsWith('/api/model-scan/upload')), 'unsupported PDF must not be uploaded');

  get('scanFile').files = [{ name: 'GTA-Guard-Safe-Test-Mod.zip', size: 514 }];
  await get('scanBtn').onclick();
  assert.equal(get('scanOut').className, 'scan-summary result-error', 'supported ZIP should enter the Standard upload path; synthetic network failure then surfaces as an error');
  assert(requests.some(url => url.includes('name=GTA-Guard-Safe-Test-Mod.zip')), 'Standard ZIP package must reach the scan upload API');

  get('scanFile').files = [{ name: 'synthetic.lua', size: 32 }];
  await get('scanBtn').onclick();
  assert(requests.some(url => url.includes('name=synthetic.lua')), 'Standard Lua script must reach the scan upload API');

  get('scanFile').files = [{ name: 'synthetic.asi', size: 8 }];
  await get('scanBtn').onclick();
  assert.equal(get('scanOut').className, 'scan-summary result-error');
  assert.equal(get('scanOut').role, 'alert');
  assert.match(get('scanOut').textContent, /Scan failed/);
  assert.equal(get('modelDiagnostics').hidden, false, 'Standard errors must expose a diagnostic code');
  assert(requests.some(url => url.includes('name=synthetic.asi')));
  console.log('✓ Scanner feedback: Standard accepts supported ZIP/Lua/ASI inputs, rejects PDF, and exposes upload failures beside the picker');
})().catch(error => { console.error(error); process.exitCode = 1; });
