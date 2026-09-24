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
assert(/Verify native PE architecture/.test(workflow) && /0xAA64/.test(workflow) && /0x8664/.test(workflow), 'release workflow must verify ARM64 and x64 PE machine types');
assert(/ARM64 payload architecture PASS, but public Setup EXE is intentionally withheld/.test(workflow), 'mislabeled x64 IExpress wrapper must not be published as ARM64 Setup');
assert(/explicitly labeled Unsigned Preview/.test(workflow), 'unsigned installer may only be published as an explicitly labeled Unsigned Preview');
assert(/SHA-256 and source-commit provenance/.test(workflow), 'unsigned preview must publish hash and exact source provenance');
assert(/never be represented as Authenticode-signed/.test(workflow), 'unsigned preview must never be represented as signed');

assert(/PACKAGE-MANIFEST\.json/.test(launcher) && /SHA256SUMS\.txt/.test(launcher), 'launcher must resolve a sealed package root');
assert(/integrity\\\\preload\.js/.test(launcher), 'launcher must preload runtime integrity verification');
assert(/127\.0\.0\.1:18777/.test(launcher), 'launcher must only open the local MalGuard UI');
assert(/--app=http:\/\/127\.0\.0\.1:18777\//.test(launcher), 'launcher should open a dedicated app window when Edge is present');
assert(/SpecialFolders\.Item\('Desktop'\)/.test(installer) && /GTA Guard\.lnk/.test(installer), 'installer must create a GTA Guard Desktop shortcut');
assert(/LOCALAPPDATA/.test(installer), 'installer must use a user-local install root');
assert(/MalGuard\.previous/.test(installer), 'installer must retain rollback staging during replacement');
assert(/NODE-LICENSE\.txt/.test(workflow), 'bundled Node license must ship with runtime');

assert(/expectedPayloadSha256/.test(installer) && /Installer payload archive integrity mismatch/.test(installer), 'installer must bind the embedded payload archive to its build-time SHA-256');
assert(/function Assert-SealedPayload/.test(installer), 'installer must verify the extracted sealed payload before replacement');
assert(/Payload SHA-256 mismatch/.test(installer), 'installer must hash-check every integrity-covered payload file');
assert(/Payload checksum coverage mismatch/.test(installer), 'installer must reject incomplete checksum coverage');
assert(/Unexpected payload file/.test(installer), 'installer must reject extra files injected into the extracted payload');
assert(/Payload contains reparse-point/.test(installer), 'installer must reject reparse-point entries in the extracted payload');
assert(/sourceCommit/.test(installer) && /Payload source provenance is invalid/.test(installer), 'installer must require embedded source provenance');
assert(/Assert-SealedPayload \$stage/.test(installer), 'payload verification must run before the installed target is replaced');

const verifyIndex = installer.indexOf('Assert-SealedPayload $stage');
const replaceIndex = installer.indexOf('Move-Item -LiteralPath $stage -Destination $target');
assert(verifyIndex >= 0 && replaceIndex > verifyIndex, 'installer must verify the payload before atomic replacement');

console.log('✓ Windows installable scanner source: pinned runtime, sealed launcher, pre-install payload verification, atomic rollback and unsigned-preview provenance gate PASS');
