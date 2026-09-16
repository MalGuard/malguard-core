'use strict';

const crypto = require('crypto');
const fs = require('fs');

const MANIFEST_SCHEMA = '1.1.0';
const PRODUCT_ID = 'MalGuard Desktop';
const MAX_PACKAGE_BYTES = 1024 * 1024 * 1024;
const MAX_MANIFEST_VALIDITY_MS = 31 * 24 * 60 * 60 * 1000;
const MAX_FUTURE_SKEW_MS = 5 * 60 * 1000;
const SEMVER_RE = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/;
const SHA256_RE = /^[a-f0-9]{64}$/;
const SOURCE_COMMIT_RE = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/;
const PACKAGE_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/;

function canonicalize(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  const type = typeof value;
  if (type === 'string' || type === 'boolean') return JSON.stringify(value);
  if (type === 'number') {
    if (!Number.isFinite(value)) throw new Error('manifest contains non-finite number');
    return JSON.stringify(value);
  }
  if (type === 'object') {
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) throw new Error('manifest contains unsupported object type');
    return `{${Object.keys(value).sort().map(key => {
      if (typeof value[key] === 'undefined') throw new Error('manifest contains undefined value');
      return `${JSON.stringify(key)}:${canonicalize(value[key])}`;
    }).join(',')}}`;
  }
  throw new Error('manifest contains unsupported value type');
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

function publicKeyFingerprint(publicKeyPem) {
  const key = crypto.createPublicKey(publicKeyPem);
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('update key must be Ed25519');
  const der = key.export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(der).digest('hex');
}

function parseTimestamp(value, label) {
  if (typeof value !== 'string' || value.length > 64) throw new Error(`invalid ${label}`);
  const ms = Date.parse(value);
  if (!Number.isFinite(ms)) throw new Error(`invalid ${label}`);
  return ms;
}

function verifyPinnedHttpsUrl(rawUrl, packageName, allowedDownloadHosts) {
  if (!Array.isArray(allowedDownloadHosts) || allowedDownloadHosts.length === 0) {
    throw new Error('trusted update download host allowlist is required');
  }
  let parsed;
  try { parsed = new URL(rawUrl); } catch (_) { throw new Error('invalid update package URL'); }
  if (parsed.protocol !== 'https:') throw new Error('update package URL must use HTTPS');
  if (parsed.username || parsed.password) throw new Error('update package URL must not contain credentials');
  const allowed = new Set(allowedDownloadHosts.map(host => String(host).toLowerCase()));
  if (!allowed.has(parsed.hostname.toLowerCase())) throw new Error('update package host is not trusted');
  let leaf;
  try { leaf = decodeURIComponent(parsed.pathname.split('/').filter(Boolean).pop() || ''); }
  catch (_) { throw new Error('invalid update package URL path'); }
  if (leaf !== packageName) throw new Error('update package URL/name mismatch');
  return true;
}

function decodeEd25519Signature(signature) {
  if (typeof signature !== 'string' || signature.length > 128) throw new Error('invalid update manifest signature');
  const bytes = Buffer.from(signature, 'base64');
  if (bytes.length !== 64 || bytes.toString('base64') !== signature) throw new Error('invalid update manifest signature');
  return bytes;
}

function verifyManifest({
  manifest,
  signature,
  publicKeyPem,
  trustedPublicKeySha256,
  currentVersion,
  expectedProduct = PRODUCT_ID,
  expectedChannel = 'stable',
  allowedDownloadHosts,
  minimumReleaseSequence = 0,
  highestSeenVersion = null,
  now = Date.now(),
  maxValidityMs = MAX_MANIFEST_VALIDITY_MS,
  maxFutureSkewMs = MAX_FUTURE_SKEW_MS,
}) {
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) throw new Error('invalid update manifest');
  if (manifest.schemaVersion !== MANIFEST_SCHEMA) throw new Error('unsupported update manifest schema');
  if (typeof currentVersion !== 'string') throw new Error('installed version is required');
  if (!SHA256_RE.test(String(trustedPublicKeySha256 || ''))) throw new Error('trusted update key fingerprint is required');

  const key = crypto.createPublicKey(publicKeyPem);
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('update key must be Ed25519');
  const actualKeyFingerprint = publicKeyFingerprint(publicKeyPem);
  if (!crypto.timingSafeEqual(Buffer.from(actualKeyFingerprint, 'hex'), Buffer.from(trustedPublicKeySha256, 'hex'))) {
    throw new Error('untrusted update signing key');
  }
  const signatureBytes = decodeEd25519Signature(signature);
  const signatureOk = crypto.verify(null, Buffer.from(canonicalize(manifest)), key, signatureBytes);
  if (!signatureOk) throw new Error('update manifest signature verification failed');

  if (manifest.product !== expectedProduct) throw new Error('unexpected update product');
  if (manifest.channel !== expectedChannel) throw new Error('unexpected update channel');
  if (!manifest.version) throw new Error('incomplete update manifest');
  if (compareVersions(manifest.version, currentVersion) <= 0) throw new Error('update is not newer than installed version');
  if (highestSeenVersion && compareVersions(manifest.version, highestSeenVersion) <= 0) {
    throw new Error('update replay or rollback detected');
  }
  if (!Number.isSafeInteger(manifest.releaseSequence) || manifest.releaseSequence <= minimumReleaseSequence) {
    throw new Error('update release sequence is stale or invalid');
  }
  if (!SOURCE_COMMIT_RE.test(String(manifest.sourceCommit || ''))) throw new Error('invalid update source commit');

  const issuedAt = parseTimestamp(manifest.issuedAt, 'update issuedAt');
  const expiresAt = parseTimestamp(manifest.expiresAt, 'update expiresAt');
  if (!Number.isFinite(now)) throw new Error('invalid update verification time');
  if (issuedAt > now + maxFutureSkewMs) throw new Error('update manifest is from the future');
  if (expiresAt <= now) throw new Error('update manifest has expired');
  if (expiresAt <= issuedAt || expiresAt - issuedAt > maxValidityMs) throw new Error('update manifest validity window is invalid');

  const pkg = manifest.package;
  if (!pkg || typeof pkg !== 'object' || Array.isArray(pkg)) throw new Error('incomplete update manifest');
  if (!PACKAGE_NAME_RE.test(String(pkg.name || ''))) throw new Error('invalid update package name');
  if (!SHA256_RE.test(String(pkg.sha256 || ''))) throw new Error('invalid package sha256');
  if (!Number.isSafeInteger(pkg.size) || pkg.size <= 0 || pkg.size > MAX_PACKAGE_BYTES) throw new Error('invalid update package size');
  verifyPinnedHttpsUrl(pkg.url, pkg.name, allowedDownloadHosts);
  return true;
}

function verifyPackageFile(filePath, expectedSha256, { expectedSize = null, maxBytes = MAX_PACKAGE_BYTES } = {}) {
  if (typeof expectedSha256 !== 'string' || !SHA256_RE.test(expectedSha256)) throw new Error('invalid expected package sha256');
  const initial = fs.lstatSync(filePath);
  if (!initial.isFile() || initial.isSymbolicLink()) throw new Error('update package must be a regular non-symlink file');
  if (initial.size <= 0 || initial.size > maxBytes) throw new Error('update package size is invalid');
  if (expectedSize != null && (!Number.isSafeInteger(expectedSize) || initial.size !== expectedSize)) {
    throw new Error('update package size mismatch');
  }

  const noFollow = Number.isInteger(fs.constants.O_NOFOLLOW) ? fs.constants.O_NOFOLLOW : 0;
  const fd = fs.openSync(filePath, fs.constants.O_RDONLY | noFollow);
  let actual;
  try {
    const before = fs.fstatSync(fd);
    if (!before.isFile() || before.size !== initial.size || before.mtimeMs !== initial.mtimeMs) {
      throw new Error('update package changed before verification');
    }
    const hash = crypto.createHash('sha256');
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    for (;;) {
      const bytesRead = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      hash.update(buffer.subarray(0, bytesRead));
    }
    const after = fs.fstatSync(fd);
    if (after.size !== before.size || after.mtimeMs !== before.mtimeMs) throw new Error('update package changed during verification');
    actual = hash.digest('hex');
  } finally {
    fs.closeSync(fd);
  }

  const finalStat = fs.lstatSync(filePath);
  if (!finalStat.isFile() || finalStat.isSymbolicLink() || finalStat.size !== initial.size || finalStat.mtimeMs !== initial.mtimeMs) {
    throw new Error('update package changed after verification');
  }
  if (!crypto.timingSafeEqual(Buffer.from(actual, 'hex'), Buffer.from(expectedSha256, 'hex'))) {
    throw new Error('update package sha256 mismatch');
  }
  return true;
}

function verifyUpdatePackage({ filePath, manifest }) {
  if (!manifest || !manifest.package) throw new Error('verified update manifest is required');
  return verifyPackageFile(filePath, manifest.package.sha256, { expectedSize: manifest.package.size });
}

module.exports = {
  MANIFEST_SCHEMA,
  PRODUCT_ID,
  MAX_PACKAGE_BYTES,
  canonicalize,
  compareVersions,
  publicKeyFingerprint,
  verifyManifest,
  verifyPackageFile,
  verifyUpdatePackage,
};
