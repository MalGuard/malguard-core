'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { canonicalize, compareVersions, verifyManifest, verifyPackageFile } = require('../desktop-app/update/secure-update');

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
const packageBytes = Buffer.from('harmless synthetic MalGuard update fixture\n');
const sha256 = crypto.createHash('sha256').update(packageBytes).digest('hex');
const manifest = {
  schemaVersion: '1.0.0',
  version: '1.0.1',
  channel: 'stable',
  package: { name: 'malguard-desktop-1.0.1.zip', sha256, size: packageBytes.length },
};
const signature = crypto.sign(null, Buffer.from(canonicalize(manifest)), privateKey).toString('base64');

assert.equal(compareVersions('1.0.1', '1.0.0'), 1);
assert.equal(compareVersions('1.0.0', '1.0.0'), 0);
assert.equal(compareVersions('0.9.9', '1.0.0'), -1);
assert.equal(verifyManifest({ manifest, signature, publicKeyPem, currentVersion: '1.0.0' }), true);

const tampered = JSON.parse(JSON.stringify(manifest));
tampered.package.size += 1;
assert.throws(() => verifyManifest({ manifest: tampered, signature, publicKeyPem, currentVersion: '1.0.0' }), /signature verification failed/);
assert.throws(() => verifyManifest({ manifest, signature, publicKeyPem, currentVersion: '1.0.1' }), /not newer/);

const wrongKey = crypto.generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' });
assert.throws(() => verifyManifest({ manifest, signature, publicKeyPem: wrongKey, currentVersion: '1.0.0' }), /signature verification failed/);

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'malguard-update-'));
const fixture = path.join(dir, 'package.bin');
fs.writeFileSync(fixture, packageBytes);
assert.equal(verifyPackageFile(fixture, sha256), true);
fs.appendFileSync(fixture, 'tamper');
assert.throws(() => verifyPackageFile(fixture, sha256), /sha256 mismatch/);
fs.rmSync(dir, { recursive: true, force: true });

console.log('✓ Secure update trust chain: Ed25519 signature, anti-downgrade and package SHA-256 PASS');
