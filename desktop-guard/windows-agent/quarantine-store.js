'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { hashFile } = require('./file-integrity.js');
const { normalizeAbsolute, assertWithinAny, isWithin } = require('./path-guard.js');

async function movePreservingIdentity(source, destination, expectedIdentity = null) {
  const before = await hashFile(source);
  if (expectedIdentity && (before.sha256 !== expectedIdentity.sha256 || before.size !== expectedIdentity.size)) {
    const error = new Error('source identity changed before move');
    error.code = 'SOURCE_IDENTITY_CHANGED';
    throw error;
  }

  try {
    await fs.promises.rename(source, destination);
  } catch (error) {
    if (!error || error.code !== 'EXDEV') throw error;
    const temp = `${destination}.${crypto.randomUUID()}.partial`;
    try {
      await fs.promises.copyFile(source, temp, fs.constants.COPYFILE_EXCL);
      const copied = await hashFile(temp);
      if (copied.sha256 !== before.sha256 || copied.size !== before.size) {
        const integrityError = new Error('cross-volume copy integrity mismatch');
        integrityError.code = 'MOVE_COPY_INTEGRITY_FAILED';
        throw integrityError;
      }
      await fs.promises.rename(temp, destination);
      await fs.promises.unlink(source);
    } catch (copyError) {
      await fs.promises.unlink(temp).catch(() => {});
      throw copyError;
    }
  }

  const after = await hashFile(destination);
  if (after.sha256 !== before.sha256 || after.size !== before.size) {
    const error = new Error('move integrity mismatch');
    error.code = 'MOVE_INTEGRITY_FAILED';
    throw error;
  }
  return after;
}

class QuarantineStore {
  constructor(rootPath, options = {}) {
    this.rootPath = normalizeAbsolute(rootPath);
    this.filesDir = path.join(this.rootPath, 'files');
    this.manifestDir = path.join(this.rootPath, 'manifests');
    this.allowedRestoreRoots = Array.isArray(options.allowedRestoreRoots)
      ? options.allowedRestoreRoots.map(normalizeAbsolute)
      : [];
  }

  _validateId(id) {
    const value = String(id || '');
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)) {
      const error = new Error('invalid quarantine id');
      error.code = 'INVALID_QUARANTINE_ID';
      throw error;
    }
    return value;
  }

  async init() {
    await fs.promises.mkdir(this.filesDir, { recursive: true });
    await fs.promises.mkdir(this.manifestDir, { recursive: true });
  }

  _manifestPath(id) { id = this._validateId(id); return path.join(this.manifestDir, `${id}.json`); }
  _filePath(id) { id = this._validateId(id); return path.join(this.filesDir, `${id}.quarantine`); }

  async _writeManifestAtomic(id, manifest, createOnly = false) {
    const finalPath = this._manifestPath(id);
    const tempPath = `${finalPath}.${crypto.randomUUID()}.tmp`;
    await fs.promises.writeFile(tempPath, JSON.stringify(manifest, null, 2), { flag: 'wx' });
    try {
      if (createOnly) {
        try {
          await fs.promises.access(finalPath, fs.constants.F_OK);
          const error = new Error('manifest already exists');
          error.code = 'MANIFEST_EXISTS';
          throw error;
        } catch (error) {
          if (error && error.code !== 'ENOENT') throw error;
        }
      }
      await fs.promises.rename(tempPath, finalPath);
    } catch (error) {
      await fs.promises.unlink(tempPath).catch(() => {});
      throw error;
    }
  }

  async quarantine(filePath, metadata = {}) {
    await this.init();
    const source = normalizeAbsolute(filePath);
    const before = await hashFile(source);
    const id = crypto.randomUUID();
    const destination = this._filePath(id);
    const originalPath = normalizeAbsolute(metadata.originalPath || source);

    const pending = {
      schemaVersion: '1.0.0',
      id,
      state: 'pending',
      originalPath,
      quarantinedPath: destination,
      sha256: before.sha256,
      size: before.size,
      verdict: metadata.verdict || 'INCONCLUSIVE',
      reason: metadata.reason || 'unspecified',
      action: metadata.action || 'hold',
      modName: metadata.modName || path.basename(path.dirname(source)) || 'Unknown mod',
      responsibleFile: metadata.responsibleFile || path.basename(source),
      createdAt: Date.now(),
    };
    await this._writeManifestAtomic(id, pending, true);

    try {
      const after = await movePreservingIdentity(source, destination, before);
      const manifest = Object.freeze({
        ...pending,
        state: 'quarantined',
        sha256: after.sha256,
        size: after.size,
        quarantinedAt: Date.now(),
      });
      await this._writeManifestAtomic(id, manifest, false);
      return manifest;
    } catch (error) {
      const failed = { ...pending, state: 'failed', failureCode: error && error.code ? error.code : 'QUARANTINE_FAILED', failedAt: Date.now() };
      await this._writeManifestAtomic(id, failed, false).catch(() => {});
      throw error;
    }
  }

  async getManifest(id) {
    const raw = await fs.promises.readFile(this._manifestPath(id), 'utf8');
    return JSON.parse(raw);
  }

  async restore(id) {
    id = this._validateId(id);
    const manifest = await this.getManifest(id);
    if (!manifest || manifest.id !== id || manifest.state !== 'quarantined') {
      const error = new Error('quarantine entry is not restorable');
      error.code = 'QUARANTINE_NOT_RESTORABLE';
      throw error;
    }
    // Never trust manifest.quarantinedPath as an authority. The payload location
    // is derived from the validated ID and the store root, preventing a tampered
    // manifest from turning restore into an arbitrary-file mover.
    const source = this._filePath(id);
    const target = normalizeAbsolute(manifest.originalPath);
    if (this.allowedRestoreRoots.length) assertWithinAny(target, this.allowedRestoreRoots);
    if (!isWithin(source, this.rootPath)) {
      const error = new Error('quarantine payload escaped store root');
      error.code = 'QUARANTINE_PATH_ESCAPE';
      throw error;
    }
    const current = await hashFile(source);
    if (current.sha256 !== manifest.sha256 || current.size !== manifest.size) {
      const error = new Error('quarantined file integrity mismatch');
      error.code = 'RESTORE_INTEGRITY_FAILED';
      throw error;
    }

    try {
      await fs.promises.access(target, fs.constants.F_OK);
      const error = new Error('restore target already exists');
      error.code = 'RESTORE_TARGET_EXISTS';
      throw error;
    } catch (error) {
      if (error && error.code !== 'ENOENT') throw error;
    }

    await fs.promises.mkdir(path.dirname(target), { recursive: true });
    const restoredIdentity = await movePreservingIdentity(source, target, current);
    const updated = {
      ...manifest,
      state: 'restored',
      restoredAt: Date.now(),
      restored: true,
      restoredSha256: restoredIdentity.sha256,
    };
    await this._writeManifestAtomic(id, updated, false);
    return updated;
  }

  async list() {
    await this.init();
    const names = await fs.promises.readdir(this.manifestDir);
    const out = [];
    for (const name of names.filter(name => name.endsWith('.json')).sort()) {
      try {
        const raw = await fs.promises.readFile(path.join(this.manifestDir, name), 'utf8');
        out.push(JSON.parse(raw));
      } catch (_) {}
    }
    return out;
  }
}

module.exports = { QuarantineStore, movePreservingIdentity };
