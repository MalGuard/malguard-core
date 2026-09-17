'use strict';

const { MalGuardMicroVMBackend } = require('./malguard-microvm-backend.js');
const { MalGuardVmBackend } = require('./malguard-vm-backend.js');
const { WindowsSandboxBackend } = require('./windows-sandbox-backend.js');

const BACKENDS = Object.freeze(['microvm', 'portable-vm', 'windows-sandbox']);

class IsolationBackendRouter {
  constructor({
    microVmBackend = null,
    portableVmBackend = null,
    windowsSandboxBackend = null,
    prefer = 'microvm',
  } = {}) {
    this.microVmBackend = microVmBackend || new MalGuardMicroVMBackend();
    this.portableVmBackend = portableVmBackend || new MalGuardVmBackend();
    this.windowsSandboxBackend = windowsSandboxBackend || new WindowsSandboxBackend();
    this.prefer = BACKENDS.includes(prefer) ? prefer : 'microvm';
    this._active = null;
  }

  _backend(name) {
    if (name === 'microvm') return this.microVmBackend;
    if (name === 'portable-vm') return this.portableVmBackend;
    return this.windowsSandboxBackend;
  }

  _order() {
    return [this.prefer, ...BACKENDS.filter(name => name !== this.prefer)];
  }

  async _caps(name) {
    return this._backend(name).capabilities();
  }

  async capabilities() {
    const capsByName = {};
    for (const name of BACKENDS) capsByName[name] = await this._caps(name);

    let selected = this._active && BACKENDS.includes(this._active) ? this._active : null;
    if (!selected) {
      selected = this._order().find(name => capsByName[name].releaseGrade === true)
        || this._order().find(name => capsByName[name].available === true)
        || this.prefer;
    }
    const active = capsByName[selected];
    return {
      ...active,
      backend: 'malguard-isolation-router',
      selectedBackend: selected,
      preferredBackend: this.prefer,
      releaseGrade: active.releaseGrade === true,
      hardened: active.releaseGrade === true,
      alternatives: {
        microvm: {
          available: capsByName.microvm.available === true,
          releaseGrade: capsByName.microvm.releaseGrade === true,
          blockers: capsByName.microvm.blockers || [],
        },
        portableVm: {
          available: capsByName['portable-vm'].available === true,
          releaseGrade: capsByName['portable-vm'].releaseGrade === true,
          requiresWindowsSandbox: capsByName['portable-vm'].requiresWindowsSandbox === true,
          requiresVtxAmdV: capsByName['portable-vm'].requiresVtxAmdV,
          blockers: capsByName['portable-vm'].blockers || [],
        },
        windowsSandbox: {
          available: capsByName['windows-sandbox'].available === true,
          releaseGrade: capsByName['windows-sandbox'].releaseGrade === true,
          blockers: capsByName['windows-sandbox'].blockers || [],
        },
      },
    };
  }

  async runContainmentSelfTest() {
    const failures = [];
    for (const name of this._order()) {
      const backend = this._backend(name);
      const result = await backend.runContainmentSelfTest();
      if (result && result.ok === true) {
        this._active = name;
        return { ...result, backend: name };
      }
      failures.push({ backend: name, code: result && result.code ? result.code : 'CONTAINMENT_SELF_TEST_FAILED' });
    }
    this._active = null;
    return { ok: false, code: 'NO_ISOLATION_BACKEND_CONTAINMENT_CERTIFIED', failures };
  }

  async runIsolationSelfTest() {
    const failures = [];
    const candidates = this._active
      ? [this._active, ...this._order().filter(name => name !== this._active)]
      : this._order();

    for (const name of candidates) {
      const backend = this._backend(name);
      if (name !== this._active) {
        const containment = await backend.runContainmentSelfTest();
        if (!containment || containment.ok !== true) {
          failures.push({ backend: name, code: containment && containment.code ? containment.code : 'CONTAINMENT_SELF_TEST_FAILED' });
          continue;
        }
      }
      const isolation = await backend.runIsolationSelfTest();
      if (isolation && isolation.ok === true) {
        this._active = name;
        return { ...isolation, backend: name };
      }
      failures.push({ backend: name, code: isolation && isolation.code ? isolation.code : 'ISOLATION_SELF_TEST_FAILED' });
    }

    this._active = null;
    return { ok: false, code: 'NO_ISOLATION_BACKEND_ISOLATION_CERTIFIED', failures };
  }

  async analyze(samplePath, expectedIdentity = null) {
    if (!this._active) {
      const caps = await this.capabilities();
      if (caps.releaseGrade !== true) {
        return { ok: false, verdict: 'inconclusive', code: 'NO_RELEASE_GRADE_ISOLATION_BACKEND', backend: caps };
      }
      this._active = caps.selectedBackend;
    }
    return this._backend(this._active).analyze(samplePath, expectedIdentity);
  }
}

module.exports = { IsolationBackendRouter, BACKENDS };
