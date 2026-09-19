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
  verifyOnlineUpdateManifest,
  verifyPackageFile,
  verifyOnlineUpdatePackage,
} = require('../desktop-app/update/secure-update');

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
const trustedPublicKeySha256 = publicKeyFingerprint(publicKeyPem);
const packageBytes = Buffer.from('harmless synthetic MalGuard update fixture\n');
const sha256 = crypto.createHash('sha256').update(packageBytes).digest('hex');

function sign(manifest, key = privateKey) {
  return crypto.sign(null, Buffer.from(canonicalize(manifest)), key).toString('base64');
}

const legacyManifest = {
  schemaVersion: '1.0.0',
  version: '1.0.1',
  channel: 'stable',
  package: { name: 'malguard-desktop-1.0.1.zip', sha256, size: packageBytes.length },
};
const legacySignature = sign(legacyManifest);

assert.equal(compareVersions('1.0.1', '1.0.0'), 1);
assert.equal(compareVersions('1.0.0', '1.0.0'), 0);
assert.equal(compareVersions('0.9.9', '1.0.0'), -1);
assert.equal(compareVersions('1.0.0', '1.0.0-rc.1'), 1);
assert.equal(compareVersions('1.0.0-rc.2', '1.0.0-rc.1'), 1);
assert.equal(compareVersions('1.0.0-rc.1', '1.0.0'), -1);
assert.equal(compareVersions('1.0.0-beta.11', '1.0.0-rc.1'), -1);
assert.throws(() => compareVersions('1.0.0-01', '1.0.0'), /invalid semantic version/);
assert.equal(verifyManifest({ manifest: legacyManifest, signature: legacySignature, publicKeyPem, currentVersion: '1.0.0' }), true);

const tamperedLegacy = JSON.parse(JSON.stringify(legacyManifest));
tamperedLegacy.package.size += 1;
assert.throws(() => verifyManifest({ manifest: tamperedLegacy, signature: legacySignature, publicKeyPem, currentVersion: '1.0.0' }), /signature verification failed/);
assert.throws(() => verifyManifest({ manifest: legacyManifest, signature: legacySignature, publicKeyPem, currentVersion: '1.0.1' }), /not newer/);

const wrongKey = crypto.generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' });
assert.throws(() => verifyManifest({ manifest: legacyManifest, signature: legacySignature, publicKeyPem: wrongKey, currentVersion: '1.0.0' }), /signature verification failed/);

const now = Date.parse('2026-09-16T10:00:00.000Z');
function onlineManifest(overrides = {}) {
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
      url: 'https://updates.malguard.example/malguard-desktop-1.0.1.zip',
    },
  };
  const next = JSON.parse(JSON.stringify(base));
  for (const [key, value] of Object.entries(overrides)) {
    if (key === 'package') next.package = { ...next.package, ...value };
    else next[key] = value;
  }
  return next;
}

function verifyOnline(manifest, signature = sign(manifest), overrides = {}) {
  return verifyOnlineUpdateManifest({
    manifest,
    signature,
    publicKeyPem,
    trustedPublicKeySha256,
    currentVersion: '1.0.0',
    expectedChannel: 'stable',
    allowedDownloadHosts: ['updates.malguard.example'],
    minimumReleaseSequence: 100,
    now,
    ...overrides,
  });
}

const online = onlineManifest();
assert.equal(verifyOnline(online), true);

const explicitlyAllowedPort = onlineManifest({
  package: { url: 'https://updates.malguard.example:4443/malguard-desktop-1.0.1.zip' },
});
assert.equal(verifyOnline(explicitlyAllowedPort, sign(explicitlyAllowedPort), {
  allowedDownloadHosts: ['https://updates.malguard.example:4443'],
}), true, 'a non-default HTTPS port must require an explicitly pinned origin');
assert.throws(() => verifyOnline(online, sign(online), { highestSeenVersion: '1.0.1' }), /replay or rollback/);
assert.throws(() => verifyOnline(online, sign(online), { minimumReleaseSequence: 101 }), /release sequence/);

const wrongKeyPair = crypto.generateKeyPairSync('ed25519');
const wrongKeyPem = wrongKeyPair.publicKey.export({ type: 'spki', format: 'pem' });
assert.throws(() => verifyOnlineUpdateManifest({
  manifest: online,
  signature: sign(online),
  publicKeyPem: wrongKeyPem,
  trustedPublicKeySha256,
  currentVersion: '1.0.0',
  allowedDownloadHosts: ['updates.malguard.example'],
  minimumReleaseSequence: 100,
  now,
}), /untrusted update signing key/);

for (const [changed, pattern] of [
  [onlineManifest({ channel: 'beta' }), /unexpected update channel/],
  [onlineManifest({ product: 'Not MalGuard' }), /unexpected update product/],
  [onlineManifest({ sourceCommit: 'not-a-commit' }), /invalid update source commit/],
  [onlineManifest({ expiresAt: '2026-09-16T09:59:00.000Z' }), /expired/],
  [onlineManifest({ issuedAt: '2026-09-16T10:10:00.000Z' }), /from the future/],
  [onlineManifest({ package: { url: 'http://updates.malguard.example/malguard-desktop-1.0.1.zip' } }), /must use HTTPS/],
  [onlineManifest({ package: { url: 'https://evil.example/malguard-desktop-1.0.1.zip' } }), /origin is not trusted/],
  [onlineManifest({ package: { url: 'https://updates.malguard.example:4443/malguard-desktop-1.0.1.zip' } }), /origin is not trusted/],
  [onlineManifest({ package: { url: 'https://updates.malguard.example/other.zip' } }), /URL\/name mismatch/],
]) {
  assert.throws(() => verifyOnline(changed, sign(changed)), pattern);
}

assert.throws(() => verifyOnlineUpdateManifest({
  manifest: online,
  signature: sign(online),
  publicKeyPem,
  trustedPublicKeySha256,
  currentVersion: '1.0.0',
  minimumReleaseSequence: 100,
  now,
}), /origin allowlist is required/);

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'malguard-update-'));
const fixture = path.join(dir, 'package.bin');
fs.writeFileSync(fixture, packageBytes);
assert.equal(verifyPackageFile(fixture, sha256, { expectedSize: packageBytes.length }), true);
assert.equal(verifyOnlineUpdatePackage({ filePath: fixture, manifest: online }), true);
assert.throws(() => verifyPackageFile(fixture, ''), /invalid expected package sha256/);
assert.throws(() => verifyPackageFile(fixture, 'not-a-sha256'), /invalid expected package sha256/);
assert.throws(() => verifyPackageFile(fixture, sha256, { expectedSize: packageBytes.length + 1 }), /size mismatch/);
fs.appendFileSync(fixture, 'tamper');
assert.throws(() => verifyPackageFile(fixture, sha256), /sha256 mismatch/);
fs.rmSync(dir, { recursive: true, force: true });

assert.throws(() => canonicalize({ a: undefined }), /undefined value/);
console.log('✓ Secure update trust chain: Ed25519 signature, pinned online key/origin, freshness, anti-replay and stable package verification PASS');
