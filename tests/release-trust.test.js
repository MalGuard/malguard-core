'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { publicKeyFingerprint } = require('../desktop-app/update/secure-update.js');
const {
  buildReleaseManifest,
  signReleaseManifest,
  verifySignedRelease,
} = require('../desktop-app/update/release-trust.js');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'malguard-release-trust-'));
try {
  const packagePath = path.join(dir, 'malguard-desktop-1.2.3.zip');
  fs.writeFileSync(packagePath, Buffer.from('harmless synthetic release payload\n'));
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
  const trustedPublicKeySha256 = publicKeyFingerprint(publicKeyPem);
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const sourceCommit = 'a'.repeat(40);

  const manifest = buildReleaseManifest({ version: '1.2.3', packagePath, sourceCommit });
  assert.equal(manifest.sourceCommit, sourceCommit);
  assert.equal(manifest.package.name, path.basename(packagePath));
  const signature = signReleaseManifest(manifest, privateKeyPem);
  const verifyArgs = {
    manifest,
    signature,
    publicKeyPem,
    trustedPublicKeySha256,
    packagePath,
    currentVersion: '1.2.2',
    expectedChannel: 'stable',
    expectedSourceCommit: sourceCommit,
  };
  assert.equal(verifySignedRelease(verifyArgs), true);

  assert.throws(() => verifySignedRelease({ ...verifyArgs, trustedPublicKeySha256: '0'.repeat(64) }), /untrusted release signing key/);
  assert.throws(() => verifySignedRelease({ ...verifyArgs, expectedSourceCommit: 'b'.repeat(40) }), /source commit mismatch/);
  assert.throws(() => verifySignedRelease({ ...verifyArgs, expectedChannel: 'beta' }), /unexpected release channel/);
  assert.throws(() => verifySignedRelease({ ...verifyArgs, trustedPublicKeySha256: '' }), /fingerprint is required/);
  assert.throws(() => verifySignedRelease({ ...verifyArgs, expectedSourceCommit: '' }), /expected release source commit is required/);

  const tamperedManifest = JSON.parse(JSON.stringify(manifest));
  tamperedManifest.version = '1.2.4';
  assert.throws(() => verifySignedRelease({ ...verifyArgs, manifest: tamperedManifest }), /signature verification failed/);

  fs.appendFileSync(packagePath, 'tamper');
  assert.throws(() => verifySignedRelease(verifyArgs), /(size mismatch|sha256 mismatch)/);

  assert.throws(() => buildReleaseManifest({ version: '1.2.3', packagePath, sourceCommit: 'short' }), /full 40-character SHA/);
  const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs8', format: 'pem' });
  assert.throws(() => signReleaseManifest(manifest, rsa), /Ed25519/);
} finally {
  fs.rmSync(dir, { recursive: true, force: true });
}

console.log('✓ Offline release trust: pinned Ed25519 key, expected source commit/channel and package tamper rejection PASS');
