'use strict';

const crypto = require('crypto');
const fs = require('fs');

const MANIFEST_SCHEMA = '1.0.0';
const SEMVER_RE = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/;

function canonicalize(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function parseVersion(version) {
  if (typeof version !== 'string') throw new Error('invalid semantic version');
  const match = SEMVER_RE.exec(version);
  if (!match) throw new Error('invalid semantic version');
  const prerelease = match[4] ? match[4].split('.') : [];
  for (const id of prerelease) {
    if (/^\d+$/.test(id) && id.length > 1 && id.startsWith('0')) throw new Error('invalid semantic version');
  }
  return { core: [Number(match[1]), Number(match[2]), Number(match[3])], prerelease };
}

function comparePrerelease(a, b) {
  if (!a.length && !b.length) return 0;
  if (!a.length) return 1;
  if (!b.length) return -1;
  const length = Math.max(a.length, b.length);
  for (let i = 0; i < length; i += 1) {
    if (a[i] === undefined) return -1;
    if (b[i] === undefined) return 1;
    if (a[i] === b[i]) continue;
    const aNumeric = /^\d+$/.test(a[i]);
    const bNumeric = /^\d+$/.test(b[i]);
    if (aNumeric && bNumeric) return Number(a[i]) > Number(b[i]) ? 1 : -1;
    if (aNumeric !== bNumeric) return aNumeric ? -1 : 1;
    return a[i] > b[i] ? 1 : -1;
  }
  return 0;
}

function compareVersions(a, b) {
  const av = parseVersion(a);
  const bv = parseVersion(b);
  for (let i = 0; i < 3; i += 1) {
    if (av.core[i] !== bv.core[i]) return av.core[i] > bv.core[i] ? 1 : -1;
  }
  return comparePrerelease(av.prerelease, bv.prerelease);
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
  if (typeof expectedSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(expectedSha256)) {
    throw new Error('invalid expected package sha256');
  }
  const actual = crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
  if (!crypto.timingSafeEqual(Buffer.from(actual, 'hex'), Buffer.from(expectedSha256, 'hex'))) {
    throw new Error('update package sha256 mismatch');
  }
  return true;
}

module.exports = { MANIFEST_SCHEMA, canonicalize, compareVersions, verifyManifest, verifyPackageFile };
