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
  assert(!/^\s*pull_request_target\s*:/m.test(text), `${file}: pull_request_target is forbidden for repository workflows`);

  const isNativeAppRelease = file === 'native-app-release.yml';
  if (isNativeAppRelease) {
    assert(/^on:\s*\r?\n\s{2}workflow_run:\s*$/m.test(text), `${file}: release publishing must be workflow_run-only`);
    assert(/^permissions:\s*\r?\n\s{2}actions:\s*read\s*\r?\n\s{2}contents:\s*write\s*$/m.test(text),
      `${file}: native app release must have exactly actions:read and contents:write`);
    assert(/github\.event\.workflow_run\.conclusion\s*==\s*'success'/.test(text),
      `${file}: release must require a successful source workflow`);
    assert(/github\.event\.workflow_run\.event\s*==\s*'push'/.test(text),
      `${file}: release must only accept push-triggered source workflows`);
    assert(/github\.event\.workflow_run\.head_branch\s*==\s*'main'/.test(text),
      `${file}: release must only accept main branch source workflows`);
    assert(/main_sha=.*gh api .*branches\/main/.test(text),
      `${file}: release must revalidate the current main SHA before publishing`);
    assert(!/actions\/checkout@/.test(text),
      `${file}: privileged release workflow must not checkout repository-controlled code`);
  } else {
    assert(/^permissions:\s*\r?\n\s{2}contents:\s*read\s*$/m.test(text),
      `${file}: workflow must declare top-level read-only contents permission`);
  }

  assert(!/^\s+(?:actions|checks|deployments|id-token|issues|packages|pages|pull-requests|repository-projects|security-events|statuses):\s*write\s*$/m.test(text), `${file}: workflow must not grant write-scoped token permissions`);
  assert(!/MALGUARD_RELEASE_SIGNING_PRIVATE_KEY_PEM/.test(text), `${file}: offline release signing private keys must never be referenced by GitHub Actions`);
  for (const line of lines.filter(value => value.includes('SignPath/github-action-submit-signing-request'))) {
    const ref = line.split('@')[1]?.split(/\\s|#/)[0] || '';
    assert(/^[A-Fa-f0-9]{40}$/.test(ref), `${file}: SignPath signing action must be pinned to a full commit SHA`);
  }
  for (const line of lines.filter(value => /sign-release-candidate\.js/.test(value))) {
    assert(/^\s*-\s*['"]tools\/sign-release-candidate\.js['"]\s*$/.test(line),
      `${file}: offline release signing tool may only appear as a path trigger, never as an executable workflow command`);
  }

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

  for (const line of lines) {
    if (/\bnpm\s+(?:install|ci)\b/.test(line)) {
      assert(/--ignore-scripts\b/.test(line), `${file}: npm dependency installation must disable lifecycle scripts`);
    }
  }

  if (text.includes('@microsoft/mxc-sdk@0.8.0')) {
    assert(/npm install[^\n]*--ignore-scripts[^\n]*@microsoft\/mxc-sdk@0\.8\.0/.test(text), `${file}: MXC SDK install must disable lifecycle scripts`);
  }

  if (file === 'windows-release-candidate.yml') {
    assert(/\$uri\.Port\s+-ne\s+443\b/.test(text), `${file}: pinned Node runtime download must require the default HTTPS port`);
    assert(/\$uri\.UserInfo/.test(text), `${file}: pinned Node runtime download must reject URL credentials`);
    assert(/Invoke-WebRequest[^\n]*-MaximumRedirection\s+0\b/.test(text), `${file}: pinned Node runtime download must refuse redirects`);
  }
}

assert(externalUses >= 3, 'expected external actions to be checked');
assert(checkoutUses >= 1, 'expected checkout actions to be checked');
console.log(`✓ Workflow supply-chain policy: ${files.length} workflows, ${externalUses} external actions pinned by full SHA, checkout credentials disabled, privileged native-app publishing isolated to trusted main workflow_run, lifecycle scripts blocked, offline signing isolated, SignPath action pinning enforced, runtime redirects refused`);
