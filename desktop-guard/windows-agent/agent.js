'use strict';

const path = require('path');
const contract = require('../guard-contract.js');
const policy = require('../containment-policy.js');
const incidents = require('../incident-report.js');
const { DirectoryWatcher } = require('./directory-watcher.js');
const { QuarantineStore } = require('./quarantine-store.js');
const { PendingHoldStore } = require('./hold-store.js');
const { hashFile, sameIdentity } = require('./file-integrity.js');
const { assertWithinAny, normalizeAbsolute, isWithin } = require('./path-guard.js');
const protocol = require('./protocol.js');


const PROTECTED_EXTENSIONS = new Set([
  '.asi', '.dll', '.lua', '.cs',
  '.exe', '.com', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar'
]);

function defaultShouldProtectPath(filePath) {
  const base = path.basename(String(filePath || '')).toLowerCase();
  const ext = path.extname(base);
  if (PROTECTED_EXTENSIONS.has(ext)) return true;
  // Catch active-code double extensions such as mod.lua.exe or plugin.dll.scr.
  const tokens = base.split('.').slice(1).map(x => '.' + x);
  return tokens.some(token => PROTECTED_EXTENSIONS.has(token));
}

class WindowsUserSpaceGuardAgent {
  constructor({ roots, quarantineRoot, scanner, onIncident = null, onHealth = null, shouldProtectPath = defaultShouldProtectPath }) {
    if (!Array.isArray(roots) || roots.length === 0) throw new TypeError('roots required');
    if (typeof scanner !== 'function') throw new TypeError('scanner required');
    this.roots = roots.map(normalizeAbsolute);
    this.quarantineRoot = normalizeAbsolute(quarantineRoot);
    if (this.roots.some(root => isWithin(this.quarantineRoot, root))) {
      const error = new Error('quarantine root must be outside watched game roots');
      error.code = 'QUARANTINE_INSIDE_WATCH_ROOT';
      throw error;
    }
    this.scanner = scanner;
    this.onIncident = typeof onIncident === 'function' ? onIncident : null;
    this.onHealth = typeof onHealth === 'function' ? onHealth : null;
    this.health = { state: 'stopped', reason: null, timestamp: Date.now() };
    this.shouldProtectPath = typeof shouldProtectPath === 'function' ? shouldProtectPath : defaultShouldProtectPath;
    this.store = new QuarantineStore(this.quarantineRoot, { allowedRestoreRoots: this.roots });
    this.holds = new PendingHoldStore(this.quarantineRoot, { allowedOriginalRoots: this.roots });
    this.processing = new Map();
    this.trustedIdentities = new Map();
    this.watcher = new DirectoryWatcher({
      roots: this.roots,
      onEvent: event => this._onEvent(event),
      onHealth: health => this._onHealth(health),
      shouldProtectPath: this.shouldProtectPath,
    });
  }

  hello() { return protocol.createAgentHello(); }
  handshake(coreHello) { return protocol.validateCoreHello(coreHello); }

  async _onHealth(health) {
    this.health = { ...health };
    if (this.onHealth) await this.onHealth({ ...health });
  }

  async _onEvent(event) {
    if (![contract.EVENT_TYPES.FILE_DISCOVERED, contract.EVENT_TYPES.FILE_CREATED, contract.EVENT_TYPES.FILE_CHANGED].includes(event.type)) return;
    await this.processPath(event.path, event);
  }

  async processPath(filePath, event = null) {
    const resolved = assertWithinAny(filePath, this.roots);
    if (!this.shouldProtectPath(resolved)) return { ok: true, ignored: true, reason: 'outside_protected_file_scope' };
    if (this.processing.has(resolved)) return this.processing.get(resolved);
    const task = this._processPathOnce(resolved, event).finally(() => this.processing.delete(resolved));
    this.processing.set(resolved, task);
    return task;
  }

  async _processPathOnce(filePath, event) {
    // Files that MalGuard itself just released can generate another filesystem
    // notification. Re-hash those paths and skip a duplicate scan only when the
    // exact trusted identity is still present. Any mutation falls through to the
    // normal fail-closed hold path.
    const trusted = this.trustedIdentities.get(filePath);
    if (trusted) {
      try {
        const current = await hashFile(filePath);
        if (sameIdentity(trusted, current)) {
          return { ok: true, action: contract.ACTIONS.RELEASE, verdict: contract.VERDICTS.SAFE, identity: current, trustedIdentityHit: true };
        }
        this.trustedIdentities.delete(filePath);
      } catch (error) {
        if (error && error.code === 'ENOENT') this.trustedIdentities.delete(filePath);
        else throw error;
      }
    }

    // Move the untrusted file out of the protected game tree BEFORE the expensive
    // scanner runs. This materially shrinks the user-space exposure window after
    // the filesystem notification has reached MalGuard.
    let hold;
    try {
      hold = await this.holds.stage(filePath);
    } catch (error) {
      if (error && error.code === 'ENOENT') return { ok: false, ignored: true, reason: 'file_disappeared_before_hold' };
      await this._onHealth({ state: 'degraded', reason: 'pre_scan_hold_failed', detail: { path: filePath, code: error && error.code ? error.code : 'HOLD_FAILED' }, timestamp: Date.now() });
      return { ok: false, action: contract.ACTIONS.HOLD, verdict: contract.VERDICTS.INCONCLUSIVE, code: error && error.code ? error.code : 'HOLD_FAILED' };
    }

    let scanResult;
    try {
      scanResult = await this.scanner(hold.holdPath, { identity: hold.identity, event, originalPath: filePath, held: true });
    } catch (error) {
      scanResult = { verdict: contract.VERDICTS.INCONCLUSIVE, reasons: ['scanner_error'] };
    }

    let heldIdentity;
    try {
      heldIdentity = await this.holds.verify(hold);
    } catch (error) {
      scanResult = { verdict: contract.VERDICTS.INCONCLUSIVE, reasons: ['held_file_changed_during_scan'] };
      try { heldIdentity = await hashFile(hold.holdPath); } catch (_) { heldIdentity = null; }
    }

    if (heldIdentity && !sameIdentity(hold.identity, heldIdentity)) {
      scanResult = { verdict: contract.VERDICTS.INCONCLUSIVE, reasons: ['held_file_changed_during_scan'] };
    }

    const decision = policy.decideContainment(scanResult);
    if (decision.action === contract.ACTIONS.RELEASE) {
      try {
        const released = await this.holds.release(hold);
        this.trustedIdentities.set(filePath, released.identity);
        return { ok: true, action: decision.action, verdict: scanResult.verdict, identity: released.identity, preScanHeld: true };
      } catch (error) {
        // If the original path reappears or release integrity cannot be proven,
        // never overwrite it and never silently release the held payload.
        scanResult = { verdict: contract.VERDICTS.INCONCLUSIVE, reasons: ['safe_release_failed', error && error.code ? error.code : 'RELEASE_FAILED'] };
      }
    }

    const finalDecision = policy.decideContainment(scanResult);
    let manifest;
    try {
      manifest = await this.store.quarantine(hold.holdPath, {
        originalPath: filePath,
        verdict: scanResult.verdict,
        reason: finalDecision.reason,
        action: finalDecision.action,
        modName: path.basename(path.dirname(filePath)) || 'Unknown mod',
        responsibleFile: path.basename(filePath),
      });
    } catch (error) {
      // The payload is already outside the game tree in the pending-hold store.
      // Preserve it there and surface degraded health rather than attempting a
      // risky recovery back into the protected root.
      await this._onHealth({ state: 'degraded', reason: 'quarantine_finalize_failed', detail: { path: filePath, code: error && error.code ? error.code : 'QUARANTINE_FAILED' }, timestamp: Date.now() });
      return {
        ok: false,
        action: contract.ACTIONS.HOLD,
        verdict: contract.VERDICTS.INCONCLUSIVE,
        heldPath: hold.holdPath,
        code: error && error.code ? error.code : 'QUARANTINE_FAILED',
      };
    }

    this.trustedIdentities.delete(filePath);
    const report = incidents.createIncidentReport({
      incidentId: manifest.id,
      modName: manifest.modName,
      responsibleFile: manifest.responsibleFile,
      verdict: scanResult.verdict,
      reason: Array.isArray(scanResult.reasons) && scanResult.reasons.length ? scanResult.reasons.join('; ') : finalDecision.reason,
      action: finalDecision.action,
      timestamp: Date.now(),
      source: 'windows-user-space-agent-prescan-hold',
    });
    if (this.onIncident) await this.onIncident(report, manifest);
    return { ok: true, action: finalDecision.action, verdict: scanResult.verdict, incident: report, quarantine: manifest, preScanHeld: true };
  }

  async startWatching() {
    await this.store.init();
    const result = await this.watcher.start();
    this.health = this.watcher.getHealth();
    return { ...result, health: { ...this.health } };
  }

  async stopWatching() {
    const result = await this.watcher.stop();
    this.health = this.watcher.getHealth();
    return { ...result, health: { ...this.health } };
  }
  getHealth() { return { ...this.health, watcher: this.watcher.getHealth() }; }
  async restore(quarantineId) { return this.store.restore(quarantineId); }
  async listQuarantine() { return this.store.list(); }
}

module.exports = { WindowsUserSpaceGuardAgent };
