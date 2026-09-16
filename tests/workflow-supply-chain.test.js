'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const workflowDir = path.join(root, '.github', 'workflows');
const files = fs.readdirSync(workflowDir).filter(name => /\.ya?ml$/i.test(name)).sort();
assert(files.length > 0, 'no GitHub Actions workflows found');

let remoteActions = 0;
let checkoutActions = 0;
for (const file of files) {
  const text = fs.readFileSync(path.join(workflowDir, file), 'utf8');
  assert(!/^\s*pull_request_target\s*:/m.test(text), `${file}: pull_request_target is forbidden for MalGuard validation workflows`);
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i += 1) {
    const match = /^\s*uses:\s*([^\s#]+)(?:\s+#.*)?$/.exec(lines[i]);
    if (!match) continue;
    const action = match[1];
    if (action.startsWith('./')) continue;
    remoteActions += 1;
    const at = action.lastIndexOf('@');
    assert(at > 0, `${file}:${i + 1}: remote action must include an immutable ref`);
    const ref = action.slice(at + 1);
    assert(/^[a-f0-9]{40}$/.test(ref), `${file}:${i + 1}: remote action must be pinned to a full 40-char commit SHA, got ${ref}`);

    if (action.startsWith('actions/checkout@')) {
      checkoutActions += 1;
      let persistCredentialsDisabled = false;
      const baseIndent = lines[i].match(/^\s*/)[0].length;
      for (let j = i + 1; j < Math.min(lines.length, i + 12); j += 1) {
        const trimmed = lines[j].trim();
        const indent = lines[j].match(/^\s*/)[0].length;
        if (j > i + 1 && trimmed.startsWith('- name:') && indent <= baseIndent) break;
        if (/^persist-credentials:\s*false\s*$/.test(trimmed)) persistCredentialsDisabled = true;
      }
      assert(persistCredentialsDisabled, `${file}:${i + 1}: actions/checkout must set persist-credentials: false`);
    }
  }
}

assert(remoteActions > 0, 'expected at least one remote GitHub Action');
assert(checkoutActions > 0, 'expected at least one checkout action');
console.log(`✓ Workflow supply chain: ${remoteActions} remote actions pinned by SHA; ${checkoutActions} checkouts disable persisted credentials`);
