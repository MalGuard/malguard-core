'use strict';

const fs = require('fs');
const path = require('path');
const contract = require('../guard-contract.js');
const { normalizeAbsolute, isWithin } = require('./path-guard.js');

class DirectoryWatcher {
  constructor({ roots, onEvent, onHealth = null, debounceMs = 60, reconcileMs = 2000, shouldProtectPath = null }) {
    if (!Array.isArray(roots) || roots.length === 0) throw new TypeError('roots required');
    if (typeof onEvent !== 'function') throw new TypeError('onEvent required');
    this.roots = roots.map(normalizeAbsolute);
    this.onEvent = onEvent;
    this.onHealth = typeof onHealth === 'function' ? onHealth : null;
    this.debounceMs = debounceMs;
    this.reconcileMs = Math.max(500, Number(reconcileMs) || 2000);
    this.shouldProtectPath = typeof shouldProtectPath === 'function' ? shouldProtectPath : (() => true);
    this.watchers = new Map();
    this.knownFiles = new Set();
    this.pending = new Map();
    this.active = false;
    this.reconcileTimer = null;
    this.health = { state: 'stopped', reason: null, timestamp: Date.now() };
  }

  async _reportHealth(state, reason = null, detail = null) {
    this.health = { state, reason, detail: detail || null, timestamp: Date.now() };
    if (this.onHealth) {
      try { await this.onHealth({ ...this.health }); } catch (_) { /* health reporting must not crash watcher */ }
    }
  }

  _dropWatcherTree(dir) {
    const root = normalizeAbsolute(dir);
    for (const [watched, watcher] of [...this.watchers.entries()]) {
      if (watched === root || isWithin(watched, root)) {
        try { watcher.close(); } catch (_) { /* noop */ }
        this.watchers.delete(watched);
      }
    }
  }

  async _emit(type, target, stat = null, source = 'watcher') {
    const resolved = normalizeAbsolute(target);
    if (type !== contract.EVENT_TYPES.FILE_REMOVED && !this.shouldProtectPath(resolved)) return;
    const event = {
      type,
      path: resolved,
      timestamp: Date.now(),
      size: stat ? stat.size : 0,
      source,
    };
    const valid = contract.validateGuardEvent(event);
    if (valid.ok) await this.onEvent(event);
  }

  async _snapshotDirectory(dir) {
    const entries = await fs.promises.readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        await this._watchDirectory(full);
      } else if (entry.isFile()) {
        const resolved = normalizeAbsolute(full);
        const alreadyKnown = this.knownFiles.has(resolved);
        this.knownFiles.add(resolved);
        if (!alreadyKnown && this.shouldProtectPath(resolved)) {
          let stat = null;
          try { stat = await fs.promises.lstat(resolved); } catch (_) { /* disappeared during baseline */ }
          if (stat && stat.isFile() && !stat.isSymbolicLink()) {
            await this._emit(contract.EVENT_TYPES.FILE_DISCOVERED, resolved, stat, 'baseline');
          }
        }
      }
    }
  }

  async _watchDirectory(dir) {
    const resolved = normalizeAbsolute(dir);
    if (this.watchers.has(resolved)) return;
    const stat = await fs.promises.lstat(resolved);
    if (!stat.isDirectory() || stat.isSymbolicLink()) return;

    const watcher = fs.watch(resolved, { persistent: false }, (eventType, filename) => {
      if (!filename) {
        this._reportHealth('degraded', 'watch_event_without_filename', { directory: resolved }).catch(() => {});
        return;
      }
      const target = path.join(resolved, String(filename));
      this._schedule(target, eventType);
    });
    watcher.on('error', error => {
      this._dropWatcherTree(resolved);
      this._reportHealth('degraded', 'watcher_error', { directory: resolved, code: error && error.code ? error.code : 'WATCH_ERROR' }).catch(() => {});
    });
    this.watchers.set(resolved, watcher);
    await this._snapshotDirectory(resolved);
  }

  _schedule(target, rawType) {
    const resolved = normalizeAbsolute(target);
    const existing = this.pending.get(resolved);
    if (existing) clearTimeout(existing.timer);
    const timer = setTimeout(() => {
      this.pending.delete(resolved);
      this._handle(resolved, rawType).catch(error => {
        this._reportHealth('degraded', 'event_processing_error', { path: resolved, code: error && error.code ? error.code : 'EVENT_ERROR' }).catch(() => {});
      });
    }, this.debounceMs);
    this.pending.set(resolved, { timer, rawType });
  }

  async _handle(target, rawType) {
    let stat = null;
    try { stat = await fs.promises.lstat(target); } catch (error) {
      if (!error || error.code !== 'ENOENT') throw error;
    }

    if (stat && stat.isSymbolicLink()) return;
    if (stat && stat.isDirectory()) {
      await this._watchDirectory(target);
      return;
    }

    const known = this.knownFiles.has(target);
    let type;
    if (!stat) {
      if (this.watchers.has(target)) this._dropWatcherTree(target);
      if (!known) return;
      this.knownFiles.delete(target);
      type = contract.EVENT_TYPES.FILE_REMOVED;
    } else {
      this.knownFiles.add(target);
      type = known || rawType === 'change'
        ? contract.EVENT_TYPES.FILE_CHANGED
        : contract.EVENT_TYPES.FILE_CREATED;
    }

    await this._emit(type, target, stat, 'watcher');
  }

  async _reconcile() {
    if (!this.active) return;
    let rootFailures = 0;
    for (const root of this.roots) {
      try {
        const stat = await fs.promises.lstat(root);
        if (!stat.isDirectory() || stat.isSymbolicLink()) throw Object.assign(new Error('invalid watch root'), { code: 'INVALID_WATCH_ROOT' });
        await this._watchDirectory(root);
      } catch (error) {
        rootFailures++;
        this._dropWatcherTree(root);
        await this._reportHealth('degraded', 'watch_root_unavailable', { root, code: error && error.code ? error.code : 'ROOT_ERROR' });
      }
    }
    if (rootFailures === 0 && this.watchers.size > 0 && this.health.state !== 'healthy') {
      await this._reportHealth('healthy', 'reconciled');
    }
  }

  async start() {
    if (this.active) return { ok: true, active: true, health: { ...this.health } };
    this.active = true;
    try {
      await this._reconcile();
      if (this.health.state !== 'degraded') await this._reportHealth('healthy', 'baseline_complete');
      this.reconcileTimer = setInterval(() => { this._reconcile().catch(() => {}); }, this.reconcileMs);
      if (this.reconcileTimer && typeof this.reconcileTimer.unref === 'function') this.reconcileTimer.unref();
      return { ok: this.health.state === 'healthy', active: true, roots: [...this.roots], health: { ...this.health } };
    } catch (error) {
      this.active = false;
      await this._reportHealth('degraded', 'startup_failed', { code: error && error.code ? error.code : 'START_ERROR' });
      throw error;
    }
  }

  async stop() {
    if (this.reconcileTimer) clearInterval(this.reconcileTimer);
    this.reconcileTimer = null;
    for (const watcher of this.watchers.values()) watcher.close();
    this.watchers.clear();
    for (const pending of this.pending.values()) clearTimeout(pending.timer);
    this.pending.clear();
    this.active = false;
    await this._reportHealth('stopped', 'requested');
    return { ok: true, active: false, health: { ...this.health } };
  }

  getHealth() { return { ...this.health, active: this.active, watcherCount: this.watchers.size }; }
}

module.exports = { DirectoryWatcher };
