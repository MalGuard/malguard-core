'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { canonicalize, publicKeyFingerprint } = require('../desktop-app/update/secure-update.js');
const { TrustedUpdateManager } = require('../desktop-app/update/update-manager.js');

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'malguard-update-runtime-'));
try {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
  const fingerprint = publicKeyFingerprint(publicKeyPem);
  const packagePath = path.join(root, 'malguard-desktop-1.2.4.zip');
  const packageBytes = Buffer.from('harmless synthetic update package\n');
  fs.writeFileSync(packagePath, packageBytes);
  const sha256 = crypto.createHash('sha256').update(packageBytes).digest('hex');
  const now = Date.parse('2026-09-16T18:00:00Z');

  function signedManifest(overrides = {}) {
    const manifest = {
      schemaVersion: '1.1.0',
      product: 'MalGuard Desktop',
      version: '1.2.4',
      channel: 'stable',
      releaseSequence: 42,
      sourceCommit: 'a'.repeat(40),
      issuedAt: new Date(now - 60_000).toISOString(),
      expiresAt: new Date(now + 60 * 60 * 1000).toISOString(),
      package: {
        name: path.basename(packagePath),
        sha256,
        size: packageBytes.length,
        url: `https://updates.example.invalid/releases/${path.basename(packagePath)}`,
      },
      ...overrides,
    };
    const signature = crypto.sign(null, Buffer.from(canonicalize(manifest)), privateKey).toString('base64');
    return { manifest, signature };
  }

  const statePath = path.join(root, 'state', 'update-state.json');
  const stagingRoot = path.join(root, 'staging');
  const manager = new TrustedUpdateManager({
    currentVersion: '1.2.3',
    trustedPublicKeyPem: publicKeyPem,
    trustedPublicKeySha256: fingerprint,
    allowedDownloadHosts: ['updates.example.invalid'],
    statePath,
    stagingRoot,
  });

  const candidate = signedManifest();
  const staged = manager.stageVerifiedCandidate({ ...candidate, downloadedPackagePath: packagePath, now });
  assert.equal(staged.ok, true);
  assert.equal(staged.verified, true);
  assert.equal(staged.releaseSequence, 42);
  assert.ok(fs.existsSync(staged.stagedPath));
  assert.equal(manager.verifyStagedCandidate({ stagedPath: staged.stagedPath, manifest: candidate.manifest }), true);

  assert.throws(
    () => manager.stageVerifiedCandidate({ ...candidate, downloadedPackagePath: packagePath, now }),
    /(replay|stale|not newer)/,
    'same signed update must not be accepted twice'
  );

  fs.appendFileSync(staged.stagedPath, 'tamper');
  assert.throws(
    () => manager.verifyStagedCandidate({ stagedPath: staged.stagedPath, manifest: candidate.manifest }),
    /(size mismatch|sha256 mismatch)/,
    'staged package tampering must be rejected immediately before install'
  );

  const badHost = signedManifest({
    releaseSequence: 43,
    version: '1.2.5',
    package: {
      ...candidate.manifest.package,
      url: `https://evil.example.invalid/releases/${path.basename(packagePath)}`,
    },
  });
  assert.throws(
    () => manager.verifyManifest(badHost.manifest, badHost.signature, now),
    /origin is not trusted/,
    'signed metadata must still be pinned to trusted distribution origins'
  );

  const unexpectedPort = signedManifest({
    releaseSequence: 43,
    version: '1.2.5',
    package: {
      ...candidate.manifest.package,
      url: `https://updates.example.invalid:4443/releases/${path.basename(packagePath)}`,
    },
  });
  assert.throws(
    () => manager.verifyManifest(unexpectedPort.manifest, unexpectedPort.signature, now),
    /origin is not trusted/,
    'a trusted hostname on an unexpected port must not bypass exact-origin policy'
  );

  fs.writeFileSync(statePath, '{broken json', 'utf8');
  const newer = signedManifest({ releaseSequence: 44, version: '1.2.6' });
  assert.throws(
    () => manager.verifyManifest(newer.manifest, newer.signature, now),
    /unreadable or corrupt/,
    'anti-replay state corruption must fail closed instead of resetting'
  );

  const wrongFingerprint = '0'.repeat(64);
  assert.throws(() => new TrustedUpdateManager({
    currentVersion: '1.2.3',
    trustedPublicKeyPem: publicKeyPem,
    trustedPublicKeySha256: wrongFingerprint,
    allowedDownloadHosts: ['updates.example.invalid'],
    statePath: path.join(root, 'wrong-state.json'),
    stagingRoot: path.join(root, 'wrong-stage'),
  }), /fingerprint mismatch/);
} finally {
  fs.rmSync(root, { recursive: true, force: true });
}

console.log('✓ Update runtime enforcement: signed manifest, exact-origin pinning, anti-replay state, verified staging and tamper rejection PASS');
