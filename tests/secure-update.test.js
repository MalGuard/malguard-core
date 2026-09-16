'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {
  canonicalize,
  compareVersions,
  publicKeyFingerprint,
  verifyManifest,
  verifyPackageFile,
  verifyUpdatePackage,
} = require('../desktop-app/update/secure-update');

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
const trustedPublicKeySha256 = publicKeyFingerprint(publicKeyPem);
const packageBytes = Buffer.from('harmless synthetic MalGuard update fixture\n');
const sha256 = crypto.createHash('sha256').update(packageBytes).digest('hex');
const now = Date.parse('2026-09-16T10:00:00.000Z');

function makeManifest(overrides = {}) {
  const base = {
    schemaVersion: '1.1.0',
    product: 'MalGuard Desktop',
    version: '1.0.1',
    channel: 'stable',
    releaseSequence: 101,
    sourceCommit: 'a'.repeat(40),
    issuedAt: '2026-09-16T09:55:00.000Z',
    expiresAt: '2026-09-23T09:55:00.000Z',
    package: {
      name: 'malguard-desktop-1.0.1.zip',
      sha256,
      size: packageBytes.length,
      url: 'https://releases.malguard.example/malguard-desktop-1.0.1.zip',
    },
  };
  const next = JSON.parse(JSON.stringify(base));
  for (const [key, value] of Object.entries(overrides)) {
    if (key === 'package') next.package = { ...next.package, ...value };
    else next[key] = value;
  }
  return next;
}

function sign(manifest, key = privateKey) {
  return crypto.sign(null, Buffer.from(canonicalize(manifest)), key).toString('base64');
}

function verify(manifest, signature = sign(manifest), overrides = {}) {
  return verifyManifest({
    manifest,
    signature,
    publicKeyPem,
    trustedPublicKeySha256,
    currentVersion: '1.0.0',
    expectedChannel: 'stable',
    allowedDownloadHosts: ['releases.malguard.example'],
    minimumReleaseSequence: 100,
    now,
    ...overrides,
  });
}

assert.equal(compareVersions('1.0.1', '1.0.0'), 1);
assert.equal(compareVersions('1.0.0', '1.0.0'), 0);
assert.equal(compareVersions('0.9.9', '1.0.0'), -1);
assert.equal(compareVersions('1.0.0', '1.0.0-rc.1'), 1);
assert.equal(compareVersions('1.0.0-rc.2', '1.0.0-rc.1'), 1);
assert.equal(compareVersions('1.0.0-rc.1', '1.0.0'), -1);
assert.equal(compareVersions('1.0.0-beta.11', '1.0.0-rc.1'), -1);
assert.throws(() => compareVersions('1.0.0-01', '1.0.0'), /invalid semantic version/);

const manifest = makeManifest();
const signature = sign(manifest);
assert.equal(verify(manifest, signature), true);

const tampered = JSON.parse(JSON.stringify(manifest));
tampered.package.size += 1;
assert.throws(() => verify(tampered, signature), /signature verification failed/);
assert.throws(() => verify(manifest, signature, { currentVersion: '1.0.1' }), /not newer/);
assert.throws(() => verify(manifest, signature, { highestSeenVersion: '1.0.1' }), /replay or rollback/);
assert.throws(() => verify(manifest, signature, { minimumReleaseSequence: 101 }), /release sequence/);

const wrongKeyPair = crypto.generateKeyPairSync('ed25519');
const wrongKeyPem = wrongKeyPair.publicKey.export({ type: 'spki', format: 'pem' });
assert.throws(() => verifyManifest({
  manifest,
  signature: sign(manifest),
  publicKeyPem: wrongKeyPem,
  trustedPublicKeySha256,
  currentVersion: '1.0.0',
  allowedDownloadHosts: ['releases.malguard.example'],
  minimumReleaseSequence: 100,
  now,
}), /untrusted update signing key/);

for (const [changed, pattern] of [
  [makeManifest({ channel: 'beta' }), /unexpected update channel/],
  [makeManifest({ product: 'Not MalGuard' }), /unexpected update product/],
  [makeManifest({ sourceCommit: 'not-a-commit' }), /invalid update source commit/],
  [makeManifest({ expiresAt: '2026-09-16T09:59:00.000Z' }), /expired/],
  [makeManifest({ issuedAt: '2026-09-16T10:10:00.000Z' }), /from the future/],
  [makeManifest({ package: { url: 'http://releases.malguard.example/malguard-desktop-1.0.1.zip' } }), /must use HTTPS/],
  [makeManifest({ package: { url: 'https://evil.example/malguard-desktop-1.0.1.zip' } }), /host is not trusted/],
  [makeManifest({ package: { url: 'https://releases.malguard.example/other.zip' } }), /URL\/name mismatch/],
]) {
  assert.throws(() => verify(changed, sign(changed)), pattern);
}

assert.throws(() => verifyManifest({
  manifest,
  signature,
  publicKeyPem,
  trustedPublicKeySha256,
  currentVersion: '1.0.0',
  minimumReleaseSequence: 100,
  now,
}), /host allowlist is required/);

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'malguard-update-'));
const fixture = path.join(dir, 'package.bin');
fs.writeFileSync(fixture, packageBytes);
assert.equal(verifyPackageFile(fixture, sha256, { expectedSize: packageBytes.length }), true);
assert.equal(verifyUpdatePackage({ filePath: fixture, manifest }), true);
assert.throws(() => verifyPackageFile(fixture, '', { expectedSize: packageBytes.length }), /invalid expected package sha256/);
assert.throws(() => verifyPackageFile(fixture, 'not-a-sha256'), /invalid expected package sha256/);
assert.throws(() => verifyPackageFile(fixture, sha256, { expectedSize: packageBytes.length + 1 }), /size mismatch/);
fs.appendFileSync(fixture, 'tamper');
assert.throws(() => verifyPackageFile(fixture, sha256), /sha256 mismatch/);
fs.rmSync(dir, { recursive: true, force: true });

assert.throws(() => canonicalize({ a: undefined }), /undefined value/);
console.log('✓ Secure update trust chain: pinned Ed25519 key, HTTPS origin allowlist, freshness, anti-replay, provenance and package integrity PASS');
