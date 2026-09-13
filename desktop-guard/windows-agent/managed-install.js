'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const contract = require('../guard-contract.js');
const policy = require('../containment-policy.js');
const { hashFile, sameIdentity } = require('./file-integrity.js');
const { movePreservingIdentity } = require('./quarantine-store.js');
const { normalizeAbsolute, assertWithinAny } = require('./path-guard.js');

class ManagedInstallGuard {
  constructor({ gameRoots, stagingRoot, quarantineStore, scanner }) {
    if (!Array.isArray(gameRoots) || gameRoots.length === 0) throw new TypeError('gameRoots required');
    if (!quarantineStore || typeof quarantineStore.quarantine !== 'function') throw new TypeError('quarantineStore required');
    if (typeof scanner !== 'function') throw new TypeError('scanner required');
    this.gameRoots = gameRoots.map(normalizeAbsolute);
    this.stagingRoot = normalizeAbsolute(stagingRoot);
    this.quarantineStore = quarantineStore;
    this.scanner = scanner;
  }

  async install(sourcePath, destinationPath) {
    const source = normalizeAbsolute(sourcePath);
    const destination = assertWithinAny(destinationPath, this.gameRoots);
    await fs.promises.mkdir(this.stagingRoot, { recursive: true });
    const stagePath = path.join(this.stagingRoot, `${crypto.randomUUID()}.stage`);
    await fs.promises.copyFile(source, stagePath, fs.constants.COPYFILE_EXCL);

    const before = await hashFile(stagePath);
    let scanResult;
    try {
      scanResult = await this.scanner(stagePath, { identity: before, managedInstall: true, destination });
    } catch (_) {
      scanResult = { verdict: contract.VERDICTS.INCONCLUSIVE, reasons: ['scanner_error'] };
    }
    const after = await hashFile(stagePath);
    if (!sameIdentity(before, after)) {
      scanResult = { verdict: contract.VERDICTS.INCONCLUSIVE, reasons: ['file_changed_during_scan'] };
    }

    const decision = policy.decideContainment(scanResult);
    if (decision.action !== contract.ACTIONS.RELEASE) {
      const manifest = await this.quarantineStore.quarantine(stagePath, {
        originalPath: destination,
        verdict: scanResult.verdict,
        reason: decision.reason,
        action: decision.action,
        modName: path.basename(path.dirname(destination)) || 'Unknown mod',
        responsibleFile: path.basename(destination),
      });
      return { ok: false, installed: false, verdict: scanResult.verdict, action: decision.action, quarantine: manifest };
    }

    try {
      await fs.promises.access(destination, fs.constants.F_OK);
      const error = new Error('destination already exists');
      error.code = 'INSTALL_DESTINATION_EXISTS';
      throw error;
    } catch (error) {
      if (error && error.code !== 'ENOENT') throw error;
    }

    await fs.promises.mkdir(path.dirname(destination), { recursive: true });
    const preMove = await hashFile(stagePath);
    if (!sameIdentity(after, preMove)) {
      const error = new Error('staged file changed before release');
      error.code = 'INSTALL_SOURCE_CHANGED';
      throw error;
    }
    await movePreservingIdentity(stagePath, destination, preMove);
    const installed = await hashFile(destination);
    if (!sameIdentity(after, installed)) {
      const error = new Error('post-install integrity mismatch');
      error.code = 'INSTALL_POSTCHECK_FAILED';
      throw error;
    }

    return { ok: true, installed: true, verdict: scanResult.verdict, action: decision.action, destination, identity: installed };
  }
}

module.exports = { ManagedInstallGuard };
