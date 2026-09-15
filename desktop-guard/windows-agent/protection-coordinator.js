'use strict';

class ProtectionCoordinator {
  constructor({ agent, accessGate, runtimeGuard = null, requireRuntimeProcessProtection = false, serviceMode = false, platform = process.platform, monitorIntervalMs = 2000 } = {}) {
    if (!agent || typeof agent.startWatching !== 'function' || typeof agent.stopWatching !== 'function') throw new TypeError('agent required');
    if (!accessGate || typeof accessGate.protectAll !== 'function' || typeof accessGate.restoreAll !== 'function' || typeof accessGate.status !== 'function') throw new TypeError('accessGate required');
    if (runtimeGuard && (typeof runtimeGuard.start !== 'function' || typeof runtimeGuard.stop !== 'function' || typeof runtimeGuard.status !== 'function')) throw new TypeError('runtimeGuard invalid');
    this.agent = agent;
    this.accessGate = accessGate;
    this.runtimeGuard = runtimeGuard;
    this.requireRuntimeProcessProtection = requireRuntimeProcessProtection === true;
    this.serviceMode = serviceMode === true;
    this.platform = platform;
    this.monitorIntervalMs = Math.max(500, Number(monitorIntervalMs) || 2000);
    this.timer = null;
    this.active = false;
    this.state = { ok:false, active:false, completeProtection:false, accessGateProtected:false, watcherHealthy:false, runtimeProcessHealthy:!this.requireRuntimeProcessProtection, runtimeProcessProtection:this.runtimeGuard ? this.runtimeGuard.getCachedStatus() : null, state:'stopped', reason:null, timestamp:Date.now() };
  }

  _set(next) { this.state = { ...this.state, ...next, timestamp:Date.now() }; return { ...this.state }; }
  getCachedStatus() { return { ...this.state, runtimeProcessProtection:this.state.runtimeProcessProtection ? { ...this.state.runtimeProcessProtection } : null }; }
  _stopTimer() { if (this.timer) clearInterval(this.timer); this.timer = null; }

  async _runtimeStatus(refresh = false) {
    if (!this.runtimeGuard) return null;
    return this.runtimeGuard.status({ refresh });
  }

  async _checkGate() {
    if (!this.active) return this.getCachedStatus();
    try {
      let gate = await this.accessGate.status();
      if (!gate || gate.protected !== true) {
        const repaired = await this.accessGate.protectAll();
        if (!repaired || repaired.ok !== true) throw Object.assign(new Error('folder protection unavailable'), { code:'ACCESS_GATE_REPAIR_FAILED' });
        gate = await this.accessGate.status();
      }
      const health = this.agent.getHealth ? this.agent.getHealth() : null;
      const watcherHealthy = !!(health && health.state === 'healthy' && health.watcher && health.watcher.active === true);
      const protectedNow = !!(gate && gate.protected === true);
      const runtime = await this._runtimeStatus(true);
      const runtimeProcessHealthy = this.requireRuntimeProcessProtection ? !!(runtime && runtime.ok === true && runtime.healthy === true && runtime.active === true) : true;
      const complete = protectedNow && watcherHealthy && runtimeProcessHealthy;
      return this._set({ ok:complete, active:true, completeProtection:complete, accessGateProtected:protectedNow, watcherHealthy, runtimeProcessHealthy, runtimeProcessProtection:runtime, state:complete ? 'healthy' : 'degraded', reason:complete ? 'protected' : 'protection_degraded' });
    } catch (error) {
      return this._set({ ok:false, active:true, completeProtection:false, runtimeProcessHealthy:false, state:'degraded', reason:error && error.code ? error.code : 'PROTECTION_CHECK_FAILED' });
    }
  }

  async start() {
    if (this.active && this.state.completeProtection) return { ...this.state, alreadyActive:true };
    if (this.platform !== 'win32') return this._set({ ok:false, active:false, completeProtection:false, state:'blocked', reason:'REALTIME_PROTECTION_WINDOWS_REQUIRED' });
    if (!this.serviceMode) return this._set({ ok:false, active:false, completeProtection:false, state:'blocked', reason:'REALTIME_PROTECTION_SERVICE_REQUIRED' });
    if (this.requireRuntimeProcessProtection && !this.runtimeGuard) return this._set({ ok:false, active:false, completeProtection:false, runtimeProcessHealthy:false, state:'blocked', reason:'RUNTIME_PROCESS_GUARD_REQUIRED' });
    try {
      const protectedResult = await this.accessGate.protectAll();
      if (!protectedResult || protectedResult.ok !== true) throw Object.assign(new Error('folder protection failed'), { code:'ACCESS_GATE_START_FAILED' });
      const gateStatus = await this.accessGate.status();
      if (!gateStatus || gateStatus.protected !== true) throw Object.assign(new Error('folder protection verification failed'), { code:'ACCESS_GATE_VERIFY_FAILED' });
      const watch = await this.agent.startWatching();
      const watcherHealthy = !!(watch && watch.active === true && watch.health && watch.health.state === 'healthy');
      if (!watcherHealthy) throw Object.assign(new Error('watcher failed'), { code:'WATCHER_START_FAILED' });

      let runtime = null;
      let runtimeProcessHealthy = !this.requireRuntimeProcessProtection;
      if (this.runtimeGuard) {
        runtime = await this.runtimeGuard.start();
        runtimeProcessHealthy = !!(runtime && runtime.ok === true && runtime.healthy === true && runtime.active === true);
        if (this.requireRuntimeProcessProtection && !runtimeProcessHealthy) throw Object.assign(new Error('runtime process guard failed'), { code:runtime && runtime.reason ? runtime.reason : 'RUNTIME_PROCESS_GUARD_START_FAILED' });
      }

      this.active = true;
      const complete = watcherHealthy && runtimeProcessHealthy;
      this._set({ ok:complete, active:true, completeProtection:complete, accessGateProtected:true, watcherHealthy:true, runtimeProcessHealthy, runtimeProcessProtection:runtime, state:complete ? 'healthy' : 'degraded', reason:complete ? 'protected_before_watch_and_runtime_monitor' : 'runtime_process_protection_degraded' });
      this._stopTimer();
      this.timer = setInterval(() => { this._checkGate().catch(() => {}); }, this.monitorIntervalMs);
      if (this.timer && typeof this.timer.unref === 'function') this.timer.unref();
      return this.getCachedStatus();
    } catch (error) {
      let accessGateProtected = false;
      try { const gate = await this.accessGate.status(); accessGateProtected = !!(gate && gate.protected === true); } catch (_) {}
      this.active = false;
      this._stopTimer();
      return this._set({ ok:false, active:false, completeProtection:false, accessGateProtected, watcherHealthy:false, runtimeProcessHealthy:false, runtimeProcessProtection:this.runtimeGuard ? this.runtimeGuard.getCachedStatus() : null, state:accessGateProtected ? 'fail_closed' : 'blocked', reason:error && error.code ? error.code : 'REALTIME_PROTECTION_START_FAILED' });
    }
  }

  async stop() {
    this._stopTimer();
    let runtimeStopped = true;
    let watcherStopped = true;
    let restored = false;
    let reason = 'requested';
    try {
      if (this.runtimeGuard) {
        const runtime = await this.runtimeGuard.stop();
        runtimeStopped = !!(runtime && runtime.active === false);
      }
    } catch (error) { runtimeStopped = false; reason = error && error.code ? error.code : 'RUNTIME_PROCESS_STOP_FAILED'; }
    try {
      const health = this.agent.getHealth ? this.agent.getHealth() : null;
      if (this.active || (health && health.watcher && health.watcher.active)) {
        const stopped = await this.agent.stopWatching();
        watcherStopped = !!(stopped && stopped.active === false);
      }
    } catch (error) { watcherStopped = false; if (reason === 'requested') reason = error && error.code ? error.code : 'WATCHER_STOP_FAILED'; }
    try { const result = await this.accessGate.restoreAll(); restored = !!(result && result.ok === true); }
    catch (error) { if (reason === 'requested') reason = error && error.code ? error.code : 'ACCESS_GATE_RESTORE_FAILED'; }
    this.active = false;
    const ok = runtimeStopped && watcherStopped && restored;
    return this._set({ ok, active:false, completeProtection:false, accessGateProtected:!restored, watcherHealthy:false, runtimeProcessHealthy:false, runtimeProcessProtection:this.runtimeGuard ? this.runtimeGuard.getCachedStatus() : null, state:ok ? 'stopped' : 'degraded', reason:ok ? 'requested' : reason });
  }

  async status({ refresh = false } = {}) { return refresh && this.active ? this._checkGate() : this.getCachedStatus(); }
}

module.exports = { ProtectionCoordinator };
