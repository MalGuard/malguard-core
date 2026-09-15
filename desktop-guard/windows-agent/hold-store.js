'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { hashFile } = require('./file-integrity.js');
const { normalizeAbsolute, assertWithinAny, isWithin } = require('./path-guard.js');
const { movePreservingIdentity } = require('./quarantine-store.js');

/**
 * Fast fail-closed holding area used by the real-time user-space guard.
 *
 * A protected file is moved out of the game tree before the expensive scan
 * begins. This does not eliminate the OS notification race that exists before
 * MalGuard receives the event, but it closes the much larger "scan while the
 * file is still loadable" window.
 */
class PendingHoldStore {
  constructor(rootPath, options = {}) {
    this.rootPath = normalizeAbsolute(rootPath);
    this.filesDir = path.join(this.rootPath, 'pending-holds');
    this.allowedOriginalRoots = Array.isArray(options.allowedOriginalRoots)
      ? options.allowedOriginalRoots.map(normalizeAbsolute)
      : [];
  }

  async init() {
    await fs.promises.mkdir(this.filesDir, { recursive: true });
  }

  _holdPath(id) {
    if (!/^[0-9a-f-]{36}$/i.test(String(id || ''))) {
      const error = new Error('invalid hold id');
      error.code = 'INVALID_HOLD_ID';
      throw error;
    }
    return path.join(this.filesDir, `${id}.hold`);
  }

  async stage(filePath) {
    await this.init();
    const originalPath = normalizeAbsolute(filePath);
    if (this.allowedOriginalRoots.length) assertWithinAny(originalPath, this.allowedOriginalRoots);
    if (isWithin(originalPath, this.rootPath)) {
      const error = new Error('hold source cannot already be inside hold root');
      error.code = 'HOLD_SOURCE_INSIDE_STORE';
      throw error;
    }

    const identity = await hashFile(originalPath);
    const id = crypto.randomUUID();
    const holdPath = this._holdPath(id);
    const movedIdentity = await movePreservingIdentity(originalPath, holdPath, identity);
    return Object.freeze({
      id,
      originalPath,
      holdPath,
      identity: movedIdentity,
      stagedAt: Date.now(),
    });
  }

  async verify(token) {
    if (!token || typeof token !== 'object') throw new TypeError('hold token required');
    const holdPath = this._holdPath(token.id);
    if (normalizeAbsolute(token.holdPath) !== normalizeAbsolute(holdPath)) {
      const error = new Error('hold token path mismatch');
      error.code = 'HOLD_TOKEN_PATH_MISMATCH';
      throw error;
    }
    const current = await hashFile(holdPath);
    const expected = token.identity || {};
    if (current.sha256 !== expected.sha256 || current.size !== expected.size) {
      const error = new Error('held file integrity changed');
      error.code = 'HOLD_INTEGRITY_CHANGED';
      throw error;
    }
    return current;
  }

  async release(token) {
    const current = await this.verify(token);
    const target = normalizeAbsolute(token.originalPath);
    if (this.allowedOriginalRoots.length) assertWithinAny(target, this.allowedOriginalRoots);

    try {
      await fs.promises.access(target, fs.constants.F_OK);
      const error = new Error('release target already exists');
      error.code = 'HOLD_RELEASE_TARGET_EXISTS';
      throw error;
    } catch (error) {
      if (error && error.code !== 'ENOENT') throw error;
    }

    await fs.promises.mkdir(path.dirname(target), { recursive: true });
    const restored = await movePreservingIdentity(token.holdPath, target, current);
    return { released: true, path: target, identity: restored, releasedAt: Date.now() };
  }

  async abandon(token) {
    // Intentionally does not move or delete the held payload. On any failure the
    // safest state is to keep the untrusted file outside the protected game tree.
    await this.verify(token);
    return { abandoned: true, path: token.holdPath, originalPath: token.originalPath };
  }
}

module.exports = { PendingHoldStore };
