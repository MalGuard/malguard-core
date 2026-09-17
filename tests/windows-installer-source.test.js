'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const lock = JSON.parse(fs.readFileSync(path.join(root, 'tools', 'windows-node-runtime-lock.json'), 'utf8'));
const workflow = fs.readFileSync(path.join(root, '.github', 'workflows', 'windows-release-candidate.yml'), 'utf8');
const installer = fs.readFileSync(path.join(root, 'tools', 'build-windows-installer.ps1'), 'utf8');
const launcher = fs.readFileSync(path.join(root, 'native', 'windows-launcher', 'MalGuardLauncher.cpp'), 'utf8');

assert.equal(lock.schemaVersion, '1.0.0');
assert.equal(lock.nodeVersion, '22.23.2');
assert.equal(lock.source, 'https://nodejs.org/dist/v22.23.2/');
for (const arch of ['x64', 'arm64']) {
  const entry = lock.architectures[arch];
  assert(entry && /^node-v22\.23\.2-win-(?:x64|arm64)\.zip$/.test(entry.archive), `${arch}: pinned Node archive missing`);
  assert(/^[a-f0-9]{64}$/.test(entry.sha256), `${arch}: pinned Node SHA-256 missing`);
}
assert.notEqual(lock.architectures.x64.sha256, lock.architectures.arm64.sha256);

assert(/node-version:\s*'22\.23\.2'/.test(workflow), 'Windows build tools must use an exact Node version');
assert(/untrusted Node runtime origin/.test(workflow), 'runtime download origin must be allowlisted');
assert(/Node runtime SHA-256 mismatch/.test(workflow), 'runtime archive must be hash verified');
assert(/native\/windows-launcher/.test(workflow), 'native MalGuard launcher must be compiled');
assert(/desktop-app\/bin/.test(workflow), 'launcher must be staged into the sealed package');
assert(/runtime\/node\.exe/.test(workflow), 'bundled Node runtime must be sealed into the package');
assert(/Build Windows Setup executable/.test(workflow), 'installable Setup executable must be built');
assert(/Installer Authenticode state/.test(workflow), 'installer signature state must be surfaced');
assert(/public distribution remains blocked/.test(workflow), 'unsigned RC must not be represented as a public final release');

assert(/PACKAGE-MANIFEST\.json/.test(launcher) && /SHA256SUMS\.txt/.test(launcher), 'launcher must resolve a sealed package root');
assert(/integrity\\\\preload\.js/.test(launcher), 'launcher must preload runtime integrity verification');
assert(/127\.0\.0\.1:18777/.test(launcher), 'launcher must only open the local MalGuard UI');
assert(/LOCALAPPDATA/.test(installer), 'installer must use a user-local install root');
assert(/MalGuard\.previous/.test(installer), 'installer must retain rollback staging during replacement');
assert(/NODE-LICENSE\.txt/.test(workflow), 'bundled Node license must ship with runtime');

console.log('✓ Windows installable scanner source: pinned runtime, sealed launcher, atomic user install and public-signing gate PASS');
