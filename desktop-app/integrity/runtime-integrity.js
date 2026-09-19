'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const SUMS_FILE = 'SHA256SUMS.txt';
const PACKAGE_MANIFEST = 'PACKAGE-MANIFEST.json';
const HASH_RE = /^[a-f0-9]{64}$/;

function sameFileIdentity(a, b) {
  return a.dev === b.dev
    && a.ino === b.ino
    && a.size === b.size
    && a.mtimeMs === b.mtimeMs
    && a.ctimeMs === b.ctimeMs;
}

function sha256RegularFile(filePath, expectedStat = null) {
  const noFollow = Number.isInteger(fs.constants.O_NOFOLLOW) ? fs.constants.O_NOFOLLOW : 0;
  const fd = fs.openSync(filePath, fs.constants.O_RDONLY | noFollow);
  try {
    const before = fs.fstatSync(fd);
    if (!before.isFile() || (expectedStat && !sameFileIdentity(before, expectedStat))) {
      const error = new Error('runtime integrity file changed before hashing');
      error.code = 'RUNTIME_INTEGRITY_FILE_CHANGED';
      throw error;
    }

    const hash = crypto.createHash('sha256');
    const buffer = Buffer.allocUnsafe(64 * 1024);
    for (;;) {
      const bytesRead = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      hash.update(buffer.subarray(0, bytesRead));
    }

    const after = fs.fstatSync(fd);
    if (!sameFileIdentity(before, after)) {
      const error = new Error('runtime integrity file changed during hashing');
      error.code = 'RUNTIME_INTEGRITY_FILE_CHANGED';
      throw error;
    }
    return { hash: hash.digest('hex'), stat: after };
  } finally {
    fs.closeSync(fd);
  }
}

function normalizeRelative(value) {
  if (typeof value !== 'string' || !value || value.includes('\0')) return null;
  if (value.includes('\\')) return null;
  const normalized = path.posix.normalize(value);
  if (normalized !== value || normalized === '.' || normalized.startsWith('../') || normalized.includes('/../') || path.posix.isAbsolute(normalized)) return null;
  return normalized;
}

function walkRegularFiles(root, current = root, out = []) {
  const entries = fs.readdirSync(current, { withFileTypes: true });
  for (const entry of entries) {
    const full = path.join(current, entry.name);
    const relative = path.relative(root, full).split(path.sep).join('/');
    const stat = fs.lstatSync(full);
    if (stat.isSymbolicLink()) {
      const error = new Error(`runtime integrity rejected symlink: ${relative}`);
      error.code = 'RUNTIME_INTEGRITY_SYMLINK';
      throw error;
    }
    if (stat.isDirectory()) walkRegularFiles(root, full, out);
    else if (stat.isFile()) out.push(relative);
    else {
      const error = new Error(`runtime integrity rejected non-regular entry: ${relative}`);
      error.code = 'RUNTIME_INTEGRITY_NONREGULAR_ENTRY';
      throw error;
    }
  }
  return out;
}

function fail(code, detail = null) {
  return { ok: false, sealed: true, code, detail };
}

function verifyRuntimePackageIntegrity(root, { requireSealed = false } = {}) {
  const resolvedRoot = path.resolve(root);
  const sumsPath = path.join(resolvedRoot, SUMS_FILE);
  const manifestPath = path.join(resolvedRoot, PACKAGE_MANIFEST);
  const sumsExists = fs.existsSync(sumsPath);
  const manifestExists = fs.existsSync(manifestPath);

  if (!sumsExists && !manifestExists) {
    return requireSealed
      ? { ok: false, sealed: false, code: 'RUNTIME_INTEGRITY_SEAL_MISSING' }
      : { ok: true, sealed: false, mode: 'development-unsealed', checkedFiles: 0 };
  }
  if (!sumsExists || !manifestExists) return fail('RUNTIME_INTEGRITY_SEAL_INCOMPLETE');

  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  } catch (_) {
    return fail('RUNTIME_INTEGRITY_MANIFEST_INVALID');
  }
  if (!manifest || manifest.schemaVersion !== '1.0.0' || manifest.product !== 'MalGuard Desktop' || !Number.isInteger(manifest.fileCount) || manifest.fileCount < 3) {
    return fail('RUNTIME_INTEGRITY_MANIFEST_INVALID');
  }

  const rawLines = fs.readFileSync(sumsPath, 'utf8').split(/\r?\n/).filter(Boolean);
  if (!rawLines.length || rawLines.length > 10000) return fail('RUNTIME_INTEGRITY_SUMS_INVALID');
  const expected = new Map();
  for (const line of rawLines) {
    const match = /^([a-f0-9]{64})  (.+)$/.exec(line);
    if (!match || !HASH_RE.test(match[1])) return fail('RUNTIME_INTEGRITY_SUMS_INVALID');
    const relative = normalizeRelative(match[2]);
    if (!relative || relative === SUMS_FILE || expected.has(relative)) return fail('RUNTIME_INTEGRITY_SUMS_INVALID');
    expected.set(relative, match[1]);
  }

  let actualFiles;
  try {
    actualFiles = walkRegularFiles(resolvedRoot).sort();
  } catch (error) {
    return fail(error.code || 'RUNTIME_INTEGRITY_WALK_FAILED', error.message);
  }
  const actualWithoutSums = actualFiles.filter(file => file !== SUMS_FILE);
  if (manifest.fileCount !== actualFiles.length) return fail('RUNTIME_INTEGRITY_FILE_COUNT_MISMATCH');
  if (expected.size !== actualWithoutSums.length) return fail('RUNTIME_INTEGRITY_UNEXPECTED_FILE_SET');

  for (const relative of actualWithoutSums) {
    if (!expected.has(relative)) return fail('RUNTIME_INTEGRITY_UNEXPECTED_FILE', relative);
  }

  for (const [relative, expectedHash] of expected) {
    const target = path.resolve(resolvedRoot, ...relative.split('/'));
    if (!(target === resolvedRoot || target.startsWith(resolvedRoot + path.sep))) return fail('RUNTIME_INTEGRITY_PATH_ESCAPE', relative);
    let stat;
    try { stat = fs.lstatSync(target); } catch (_) { return fail('RUNTIME_INTEGRITY_FILE_MISSING', relative); }
    if (!stat.isFile() || stat.isSymbolicLink()) return fail('RUNTIME_INTEGRITY_FILE_TYPE_INVALID', relative);
    let hashed;
    try { hashed = sha256RegularFile(target, stat); } catch (error) {
      return fail(error.code || 'RUNTIME_INTEGRITY_READ_FAILED', relative);
    }
    let finalStat;
    try { finalStat = fs.lstatSync(target); } catch (_) { return fail('RUNTIME_INTEGRITY_FILE_MISSING', relative); }
    if (!finalStat.isFile() || finalStat.isSymbolicLink() || !sameFileIdentity(finalStat, hashed.stat)) {
      return fail('RUNTIME_INTEGRITY_FILE_CHANGED', relative);
    }
    const ok = crypto.timingSafeEqual(Buffer.from(hashed.hash, 'hex'), Buffer.from(expectedHash, 'hex'));
    if (!ok) return fail('RUNTIME_INTEGRITY_HASH_MISMATCH', relative);
  }

  return {
    ok: true,
    sealed: true,
    mode: 'package-checksum-verified',
    checkedFiles: expected.size,
    packageManifest: {
      desktopVersion: typeof manifest.desktopVersion === 'string' ? manifest.desktopVersion : null,
      fileCount: manifest.fileCount,
    },
  };
}

module.exports = {
  SUMS_FILE,
  PACKAGE_MANIFEST,
  verifyRuntimePackageIntegrity,
  normalizeRelative,
};
