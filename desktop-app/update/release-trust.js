'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const {
  canonicalize,
  publicKeyFingerprint,
  verifyManifest,
  verifyPackageFile,
} = require('./secure-update.js');

const SOURCE_COMMIT_RE = /^[a-f0-9]{40}$/;
const SHA256_RE = /^[a-f0-9]{64}$/;

function fileSha256(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function buildReleaseManifest({ version, channel = 'stable', packagePath, sourceCommit }) {
  if (typeof version !== 'string' || !version) throw new Error('release version is required');
  if (typeof channel !== 'string' || !/^[a-z0-9-]{1,32}$/i.test(channel)) throw new Error('invalid release channel');
  const commit = String(sourceCommit || '').toLowerCase();
  if (!SOURCE_COMMIT_RE.test(commit)) throw new Error('release source commit must be a full 40-character SHA');
  const resolved = path.resolve(packagePath || '');
  const stat = fs.lstatSync(resolved);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size <= 0) throw new Error('release package must be a non-empty regular file');
  return {
    schemaVersion: '1.0.0',
    version,
    channel,
    sourceCommit: commit,
    package: {
      name: path.basename(resolved),
      sha256: fileSha256(resolved),
      size: stat.size,
    },
  };
}

function signReleaseManifest(manifest, privateKeyPem) {
  if (typeof privateKeyPem !== 'string' || !privateKeyPem.trim()) throw new Error('offline release signing private key is required');
  const key = crypto.createPrivateKey(privateKeyPem);
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('release signing key must be Ed25519');
  return crypto.sign(null, Buffer.from(canonicalize(manifest), 'utf8'), key).toString('base64');
}

function verifyTrustedReleaseKey(publicKeyPem, trustedPublicKeySha256) {
  const expected = String(trustedPublicKeySha256 || '').toLowerCase();
  if (!SHA256_RE.test(expected)) throw new Error('trusted release public key fingerprint is required');
  const actual = publicKeyFingerprint(publicKeyPem);
  if (!crypto.timingSafeEqual(Buffer.from(actual, 'hex'), Buffer.from(expected, 'hex'))) {
    throw new Error('untrusted release signing key');
  }
}

function verifySignedRelease({
  manifest,
  signature,
  publicKeyPem,
  trustedPublicKeySha256,
  packagePath,
  currentVersion,
  expectedChannel = 'stable',
  expectedSourceCommit,
}) {
  if (!manifest || !SOURCE_COMMIT_RE.test(String(manifest.sourceCommit || '').toLowerCase())) {
    throw new Error('release manifest source commit is invalid');
  }
  const expectedCommit = String(expectedSourceCommit || '').toLowerCase();
  if (!SOURCE_COMMIT_RE.test(expectedCommit)) throw new Error('expected release source commit is required');
  if (String(manifest.sourceCommit).toLowerCase() !== expectedCommit) throw new Error('release source commit mismatch');
  if (manifest.channel !== expectedChannel) throw new Error('unexpected release channel');

  verifyTrustedReleaseKey(publicKeyPem, trustedPublicKeySha256);

  const resolved = path.resolve(packagePath || '');
  const stat = fs.lstatSync(resolved);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size <= 0) throw new Error('release package must be a non-empty regular file');
  if (!manifest.package || manifest.package.name !== path.basename(resolved)) throw new Error('release package name mismatch');
  if (manifest.package.size !== stat.size) throw new Error('release package size mismatch');

  verifyManifest({ manifest, signature, publicKeyPem, currentVersion });
  verifyPackageFile(resolved, manifest.package.sha256, { expectedSize: manifest.package.size });
  return true;
}

module.exports = {
  SOURCE_COMMIT_RE,
  buildReleaseManifest,
  signReleaseManifest,
  verifyTrustedReleaseKey,
  verifySignedRelease,
};
