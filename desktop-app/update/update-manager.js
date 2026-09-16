'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const {
  publicKeyFingerprint,
  verifyOnlineUpdateManifest,
  verifyOnlineUpdatePackage,
} = require('./secure-update.js');

const UPDATE_STATE_SCHEMA = '1.0.0';
const MAX_STATE_BYTES = 64 * 1024;

function fail(message, code) {
  const error = new Error(message);
  error.code = code;
  throw error;
}

function assertRegularFile(filePath, code) {
  let stat;
  try { stat = fs.lstatSync(filePath); } catch (error) {
    if (error && error.code === 'ENOENT') return null;
    throw error;
  }
  if (!stat.isFile() || stat.isSymbolicLink()) fail('update security state must be a regular non-symlink file', code);
  return stat;
}

class TrustedUpdateManager {
  constructor({
    currentVersion,
    trustedPublicKeyPem,
    trustedPublicKeySha256,
    allowedDownloadHosts,
    statePath,
    stagingRoot,
    expectedProduct = 'MalGuard Desktop',
    expectedChannel = 'stable',
  }) {
    if (typeof currentVersion !== 'string' || !currentVersion) fail('current version is required', 'UPDATE_POLICY_INVALID');
    if (typeof trustedPublicKeyPem !== 'string' || !trustedPublicKeyPem.trim()) fail('trusted update public key is required', 'UPDATE_POLICY_INVALID');
    if (typeof trustedPublicKeySha256 !== 'string' || !/^[a-f0-9]{64}$/.test(trustedPublicKeySha256)) fail('trusted update key fingerprint is required', 'UPDATE_POLICY_INVALID');
    if (!Array.isArray(allowedDownloadHosts) || allowedDownloadHosts.length === 0) fail('trusted update hosts are required', 'UPDATE_POLICY_INVALID');
    if (!statePath || !stagingRoot) fail('update state and staging paths are required', 'UPDATE_POLICY_INVALID');

    const actualFingerprint = publicKeyFingerprint(trustedPublicKeyPem);
    const expected = Buffer.from(trustedPublicKeySha256, 'hex');
    const actual = Buffer.from(actualFingerprint, 'hex');
    if (!crypto.timingSafeEqual(actual, expected)) fail('trusted update key fingerprint mismatch', 'UPDATE_POLICY_INVALID');

    this.currentVersion = currentVersion;
    this.trustedPublicKeyPem = trustedPublicKeyPem;
    this.trustedPublicKeySha256 = trustedPublicKeySha256;
    this.allowedDownloadHosts = [...new Set(allowedDownloadHosts.map(host => String(host).toLowerCase()))];
    this.statePath = path.resolve(statePath);
    this.stagingRoot = path.resolve(stagingRoot);
    this.expectedProduct = expectedProduct;
    this.expectedChannel = expectedChannel;
  }

  defaultState() {
    return {
      schemaVersion: UPDATE_STATE_SCHEMA,
      highestReleaseSequence: 0,
      highestSeenVersion: this.currentVersion,
      lastSourceCommit: null,
      updatedAt: 0,
    };
  }

  loadState() {
    const stat = assertRegularFile(this.statePath, 'UPDATE_STATE_INVALID');
    if (!stat) return this.defaultState();
    if (stat.size <= 0 || stat.size > MAX_STATE_BYTES) fail('update security state size is invalid', 'UPDATE_STATE_INVALID');

    let parsed;
    try { parsed = JSON.parse(fs.readFileSync(this.statePath, 'utf8')); }
    catch (_) { fail('update security state is unreadable or corrupt', 'UPDATE_STATE_INVALID'); }

    if (!parsed || parsed.schemaVersion !== UPDATE_STATE_SCHEMA) fail('update security state schema is invalid', 'UPDATE_STATE_INVALID');
    if (!Number.isSafeInteger(parsed.highestReleaseSequence) || parsed.highestReleaseSequence < 0) fail('update release sequence state is invalid', 'UPDATE_STATE_INVALID');
    if (typeof parsed.highestSeenVersion !== 'string' || !parsed.highestSeenVersion) fail('update version state is invalid', 'UPDATE_STATE_INVALID');
    if (parsed.lastSourceCommit != null && !/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(parsed.lastSourceCommit)) fail('update source commit state is invalid', 'UPDATE_STATE_INVALID');
    return parsed;
  }

  persistState(state) {
    fs.mkdirSync(path.dirname(this.statePath), { recursive: true, mode: 0o700 });
    const temp = `${this.statePath}.${crypto.randomUUID()}.tmp`;
    const body = JSON.stringify(state, null, 2) + '\n';
    fs.writeFileSync(temp, body, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
    try {
      fs.renameSync(temp, this.statePath);
    } finally {
      try { if (fs.existsSync(temp)) fs.unlinkSync(temp); } catch (_) {}
    }
  }

  verifyManifest(manifest, signature, now = Date.now()) {
    const state = this.loadState();
    verifyOnlineUpdateManifest({
      manifest,
      signature,
      publicKeyPem: this.trustedPublicKeyPem,
      trustedPublicKeySha256: this.trustedPublicKeySha256,
      currentVersion: this.currentVersion,
      expectedProduct: this.expectedProduct,
      expectedChannel: this.expectedChannel,
      allowedDownloadHosts: this.allowedDownloadHosts,
      minimumReleaseSequence: state.highestReleaseSequence,
      highestSeenVersion: state.highestSeenVersion,
      now,
    });
    return state;
  }

  stageVerifiedCandidate({ manifest, signature, downloadedPackagePath, now = Date.now() }) {
    const state = this.verifyManifest(manifest, signature, now);
    verifyOnlineUpdatePackage({ filePath: downloadedPackagePath, manifest });

    fs.mkdirSync(this.stagingRoot, { recursive: true, mode: 0o700 });
    const stagedName = `${manifest.releaseSequence}-${manifest.package.name}`;
    const stagedPath = path.join(this.stagingRoot, stagedName);
    if (fs.existsSync(stagedPath)) fail('verified update staging target already exists', 'UPDATE_STAGE_COLLISION');

    fs.copyFileSync(downloadedPackagePath, stagedPath, fs.constants.COPYFILE_EXCL);
    try {
      try { fs.chmodSync(stagedPath, 0o600); } catch (_) {}
      verifyOnlineUpdatePackage({ filePath: stagedPath, manifest });

      const nextState = {
        schemaVersion: UPDATE_STATE_SCHEMA,
        highestReleaseSequence: manifest.releaseSequence,
        highestSeenVersion: manifest.version,
        lastSourceCommit: manifest.sourceCommit,
        updatedAt: Date.now(),
      };
      this.persistState(nextState);

      return Object.freeze({
        ok: true,
        verified: true,
        stagedPath,
        version: manifest.version,
        releaseSequence: manifest.releaseSequence,
        sourceCommit: manifest.sourceCommit,
        sha256: manifest.package.sha256,
      });
    } catch (error) {
      try { fs.unlinkSync(stagedPath); } catch (_) {}
      throw error;
    }
  }

  verifyStagedCandidate({ stagedPath, manifest }) {
    const state = this.loadState();
    if (state.highestReleaseSequence !== manifest.releaseSequence || state.highestSeenVersion !== manifest.version || state.lastSourceCommit !== manifest.sourceCommit) {
      fail('staged update no longer matches accepted anti-replay state', 'UPDATE_STAGE_STATE_MISMATCH');
    }
    verifyOnlineUpdatePackage({ filePath: stagedPath, manifest });
    return true;
  }
}

module.exports = { TrustedUpdateManager, UPDATE_STATE_SCHEMA };
