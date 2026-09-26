'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const version = fs.readFileSync(path.join(ROOT, 'DESKTOP-VERSION'), 'utf8').trim();
const out = path.join(ROOT, 'dist', `malguard-desktop-${version}`);

const run = spawnSync(process.execPath, [path.join(ROOT, 'tools', 'build-portable-package.js')], {
  cwd: ROOT,
  encoding: 'utf8',
  windowsHide: true,
});
assert.equal(run.status, 0, `portable packaging failed: ${run.stderr || run.stdout}`);

for (const required of [
  'PACKAGE-MANIFEST.json',
  'SHA256SUMS.txt',
  'package.json',
  'rules.json',
  'app.js',
  'desktop-app/server.js',
  'desktop-app/diagnostics/telemetry-consent.js',
  'desktop-app/diagnostics/telemetry-client.js',
  'desktop-app/diagnostics/telemetry-payload.js',
  'desktop-app/diagnostics/windows-device.js',
  'desktop-app/public/privacy-diagnostics.js',
  'PRIVACY.md',
  'desktop-app/gta-simulation/simulation-engine.js',
  'desktop-app/gta-simulation/ai-evidence-bridge.js',
  'desktop-app/gta-simulation/cloud-gta-simulation-client.js',
  'desktop-app/gta-simulation/malguard-cloud-ai-provider.js',
  'desktop-app/threat-intel/credential-store.js',
  'desktop-guard/windows-agent/agent.js',
]) {
  assert.ok(fs.existsSync(path.join(out, required)), `missing packaged runtime file: ${required}`);
}

const bridge = spawnSync(process.execPath, ['-e', "new (require('./desktop-app/scanner-bridge.js').ScannerBridge)()"], {
  cwd: out,
  encoding: 'utf8',
  windowsHide: true,
});
assert.equal(bridge.status, 0, `packaged scanner startup failed: ${bridge.stderr || bridge.stdout}`);

for (const forbidden of ['backend','api','migrations','node_modules']) assert.ok(!fs.existsSync(path.join(out, forbidden)), 'server/test dependencies must not ship: '+forbidden);
assert.ok(!fs.existsSync(path.join(out, 'tests')), 'tests must not ship in portable runtime package');
assert.ok(!fs.existsSync(path.join(out, '.env')), 'environment secret file must not ship');
assert.ok(!fs.existsSync(path.join(out, 'desktop-app', 'threat-intel', 'abusech-auth.dpapi')), 'DPAPI credential blob must not ship');

const manifest = JSON.parse(fs.readFileSync(path.join(out, 'PACKAGE-MANIFEST.json'), 'utf8'));
assert.equal(manifest.schemaVersion, '1.0.0');
assert.equal(manifest.desktopVersion, version);
assert.match(manifest.sourceCommit, /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/);
assert.equal(manifest.entrypoint, 'desktop-app/server.js');
assert.ok(Number.isInteger(manifest.fileCount) && manifest.fileCount > 10);

const head = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: ROOT, encoding: 'utf8', windowsHide: true });
if (head.status === 0) assert.equal(manifest.sourceCommit, head.stdout.trim().toLowerCase(), 'package provenance must match checked-out commit');

const sums = fs.readFileSync(path.join(out, 'SHA256SUMS.txt'), 'utf8').trim().split(/\r?\n/);
assert.ok(sums.some(line => line.endsWith('  PACKAGE-MANIFEST.json')), 'manifest must be integrity-covered');
for (const line of sums) {
  const match = /^([a-f0-9]{64})  (.+)$/.exec(line);
  assert.ok(match, `invalid checksum line: ${line}`);
  const file = path.join(out, ...match[2].split('/'));
  assert.ok(fs.existsSync(file), `checksum references missing file: ${match[2]}`);
  const actual = crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
  assert.equal(actual, match[1], `checksum mismatch: ${match[2]}`);
}

const packagedFiles = [];
(function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full);
    else if (entry.isFile()) packagedFiles.push(full);
  }
})(out);
assert.equal(packagedFiles.length, manifest.fileCount, 'manifest file count mismatch');

fs.rmSync(out, { recursive: true, force: true });
console.log(`✓ Packaging foundation: ${manifest.fileCount} runtime files, source provenance and SHA-256 integrity manifest PASS`);
