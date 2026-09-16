'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const workflows = path.join(root, '.github', 'workflows');
const files = fs.readdirSync(workflows)
  .filter(name => /\.ya?ml$/i.test(name))
  .sort();

assert(files.length > 0, 'expected GitHub Actions workflows');
let externalUses = 0;
let checkoutUses = 0;

for (const file of files) {
  const full = path.join(workflows, file);
  const text = fs.readFileSync(full, 'utf8');
  const lines = text.split(/\r?\n/);

  assert(!/^\s*permissions:\s*write-all\s*$/m.test(text), `${file}: write-all permissions are forbidden`);

  for (let i = 0; i < lines.length; i += 1) {
    const match = /^\s*uses:\s*([^\s#]+)(?:\s+#.*)?$/.exec(lines[i]);
    if (!match) continue;
    const spec = match[1];
    if (spec.startsWith('./') || spec.startsWith('docker://')) continue;
    externalUses += 1;
    const at = spec.lastIndexOf('@');
    assert(at > 0, `${file}:${i + 1}: external action must include an immutable ref`);
    const action = spec.slice(0, at);
    const ref = spec.slice(at + 1);
    assert(/^[A-Fa-f0-9]{40}$/.test(ref), `${file}:${i + 1}: ${action} must be pinned to a full 40-character commit SHA, not ${ref}`);

    if (action === 'actions/checkout') {
      checkoutUses += 1;
      const nearby = lines.slice(i + 1, Math.min(lines.length, i + 9)).join('\n');
      assert(/persist-credentials:\s*false/.test(nearby), `${file}:${i + 1}: checkout must disable persisted credentials`);
    }
  }

  if (text.includes('@microsoft/mxc-sdk@0.8.0')) {
    assert(/npm install[^\n]*--ignore-scripts[^\n]*@microsoft\/mxc-sdk@0\.8\.0/.test(text), `${file}: MXC SDK install must disable lifecycle scripts`);
  }
}

assert(externalUses >= 3, 'expected external actions to be checked');
assert(checkoutUses >= 1, 'expected checkout actions to be checked');
console.log(`✓ Workflow supply-chain policy: ${files.length} workflows, ${externalUses} external actions pinned by full SHA, checkout credentials disabled`);
