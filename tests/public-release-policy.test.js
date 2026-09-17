'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const workflowPath = path.join(root, '.github', 'workflows', 'windows-release-candidate.yml');
const workflow = fs.readFileSync(workflowPath, 'utf8');
const signingTool = fs.readFileSync(path.join(root, 'tools', 'sign-release-candidate.js'), 'utf8');
const verifySignedTool = fs.readFileSync(path.join(root, 'tools', 'verify-signed-release.js'), 'utf8');
const authenticodeTool = fs.readFileSync(path.join(root, 'tools', 'verify-windows-authenticode.ps1'), 'utf8');

assert(/fetch-depth:\s*2/.test(workflow), 'release workflow must fetch enough history to prove merge topology');
assert(/persist-credentials:\s*false/.test(workflow), 'release workflow must not persist checkout credentials');
assert(/github\.event_name == 'push' && github\.ref == 'refs\/heads\/main'/.test(workflow), 'release workflow must gate main pushes');
assert(/MALGUARD_PUSH_FORCED/.test(workflow), 'release workflow must reject force pushes');
assert(/parents\.Count -lt 3/.test(workflow), 'release workflow must reject single-parent/direct main commits');
assert(/MALGUARD_SOURCE_COMMIT:\s*\$\{\{ github\.sha \}\}/.test(workflow), 'release package must bind provenance to the exact workflow SHA');
assert(/Re-open and verify archived release candidate/.test(workflow), 'release workflow must re-open and verify the final archive');
assert(/verifyRuntimePackageIntegrity/.test(workflow), 're-opened archive must pass runtime integrity verification');
assert(/sourceCommit -ne \$env:MALGUARD_SOURCE_COMMIT/.test(workflow), 're-opened archive must bind embedded provenance to the workflow SHA');
assert(/name: Upload trusted-main Windows(?: installable)? release candidate[\s\S]*if: github\.event_name == 'push' && github\.ref == 'refs\/heads\/main'/.test(workflow), 'distributable release artifacts must only be uploaded from trusted main pushes');
assert(!/MALGUARD_RELEASE_SIGNING_PRIVATE_KEY_PEM/.test(workflow), 'offline release private key must never enter GitHub Actions');

assert(/GITHUB_ACTIONS === 'true'/.test(signingTool) && /OFFLINE_RELEASE_SIGNING_REQUIRED/.test(signingTool), 'release signer must refuse GitHub Actions execution');
assert(/MALGUARD_RELEASE_PUBLIC_KEY_SHA256/.test(verifySignedTool), 'offline release verification must require a pinned release public-key fingerprint');
assert(/MALGUARD_EXPECTED_SOURCE_COMMIT/.test(verifySignedTool), 'offline release verification must require the independently expected source commit');

assert(/Get-AuthenticodeSignature/.test(authenticodeTool), 'public Windows release verification must use Authenticode');
assert(/MALGUARD_WINDOWS_SIGNER_THUMBPRINT/.test(authenticodeTool), 'Authenticode verifier must pin the expected publisher certificate thumbprint');
assert(/Status -ne 'Valid'/.test(authenticodeTool), 'Authenticode verifier must fail closed on invalid signatures');

const workflowsDir = path.join(root, '.github', 'workflows');
for (const name of fs.readdirSync(workflowsDir).filter(name => /\.ya?ml$/i.test(name))) {
  const text = fs.readFileSync(path.join(workflowsDir, name), 'utf8');
  assert(!/MALGUARD_RELEASE_SIGNING_PRIVATE_KEY_PEM/.test(text), `${name}: offline release private key reference is forbidden in CI`);
}

console.log('✓ Public release policy: trusted-main-only artifacts, archive re-verification, pinned offline trust and Authenticode fail-closed verification PASS');
