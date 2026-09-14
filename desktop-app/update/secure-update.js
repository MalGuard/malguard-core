'use strict';

const crypto = require('crypto');
const fs = require('fs');

const MANIFEST_SCHEMA = '1.0.0';

function canonicalize(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function parseVersion(version) {
  if (typeof version !== 'string' || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version)) {
    throw new Error('invalid semantic version');
  }
  return version.split('-')[0].split('.').map(Number);
}

function compareVersions(a, b) {
  const av = parseVersion(a);
  const bv = parseVersion(b);
  for (let i = 0; i < 3; i += 1) {
    if (av[i] !== bv[i]) return av[i] > bv[i] ? 1 : -1;
  }
  return 0;
}

function verifyManifest({ manifest, signature, publicKeyPem, currentVersion }) {
  if (!manifest || manifest.schemaVersion !== MANIFEST_SCHEMA) throw new Error('unsupported update manifest schema');
  if (!manifest.version || !manifest.package || !manifest.package.sha256) throw new Error('incomplete update manifest');
  if (!/^[a-f0-9]{64}$/.test(manifest.package.sha256)) throw new Error('invalid package sha256');
  if (compareVersions(manifest.version, currentVersion) <= 0) throw new Error('update is not newer than installed version');

  const key = crypto.createPublicKey(publicKeyPem);
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('update key must be Ed25519');
  const ok = crypto.verify(null, Buffer.from(canonicalize(manifest)), key, Buffer.from(signature, 'base64'));
  if (!ok) throw new Error('update manifest signature verification failed');
  return true;
}

function verifyPackageFile(filePath, expectedSha256) {
  const actual = crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
  if (!crypto.timingSafeEqual(Buffer.from(actual, 'hex'), Buffer.from(expectedSha256, 'hex'))) {
    throw new Error('update package sha256 mismatch');
  }
  return true;
}

module.exports = { MANIFEST_SCHEMA, canonicalize, compareVersions, verifyManifest, verifyPackageFile };
