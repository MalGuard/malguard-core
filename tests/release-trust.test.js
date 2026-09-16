'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
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
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const sourceCommit = 'a'.repeat(40);

  const manifest = buildReleaseManifest({ version: '1.2.3', packagePath, sourceCommit });
  assert.equal(manifest.sourceCommit, sourceCommit);
  assert.equal(manifest.package.name, path.basename(packagePath));
  const signature = signReleaseManifest(manifest, privateKeyPem);
  assert.equal(verifySignedRelease({ manifest, signature, publicKeyPem, packagePath, currentVersion: '1.2.2' }), true);

  const tamperedManifest = JSON.parse(JSON.stringify(manifest));
  tamperedManifest.sourceCommit = 'b'.repeat(40);
  assert.throws(() => verifySignedRelease({ manifest: tamperedManifest, signature, publicKeyPem, packagePath, currentVersion: '1.2.2' }), /signature verification failed/);

  fs.appendFileSync(packagePath, 'tamper');
  assert.throws(() => verifySignedRelease({ manifest, signature, publicKeyPem, packagePath, currentVersion: '1.2.2' }), /(size mismatch|sha256 mismatch)/);

  assert.throws(() => buildReleaseManifest({ version: '1.2.3', packagePath, sourceCommit: 'short' }), /full 40-character SHA/);
  const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs8', format: 'pem' });
  assert.throws(() => signReleaseManifest(manifest, rsa), /Ed25519/);
} finally {
  fs.rmSync(dir, { recursive: true, force: true });
}

console.log('✓ Offline release trust: source commit binding, Ed25519 signature and package identity tamper rejection PASS');
