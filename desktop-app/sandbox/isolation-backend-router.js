'use strict';

const { MalGuardMicroVMBackend } = require('./malguard-microvm-backend.js');
const { WindowsSandboxBackend } = require('./windows-sandbox-backend.js');

class IsolationBackendRouter {
  constructor({ microVmBackend = null, windowsSandboxBackend = null, prefer = 'microvm' } = {}) {
    this.microVmBackend = microVmBackend || new MalGuardMicroVMBackend();
    this.windowsSandboxBackend = windowsSandboxBackend || new WindowsSandboxBackend();
    this.prefer = prefer === 'windows-sandbox' ? 'windows-sandbox' : 'microvm';
    this._active = null;
  }

  _backend(name) {
    return name === 'microvm' ? this.microVmBackend : this.windowsSandboxBackend;
  }

  async _caps(name) {
    return this._backend(name).capabilities();
  }

  async capabilities() {
    const microvm = await this._caps('microvm');
    const windows = await this._caps('windows-sandbox');
    let selected = this._active;
    if (!selected) {
      if (this.prefer === 'microvm' && microvm.releaseGrade === true) selected = 'microvm';
      else if (windows.releaseGrade === true) selected = 'windows-sandbox';
      else if (this.prefer === 'microvm' && microvm.available === true) selected = 'microvm';
      else if (windows.available === true) selected = 'windows-sandbox';
      else selected = this.prefer === 'microvm' ? 'microvm' : 'windows-sandbox';
    }
    const active = selected === 'microvm' ? microvm : windows;
    return {
      ...active,
      backend: 'malguard-isolation-router',
      selectedBackend: selected,
      preferredBackend: this.prefer,
      releaseGrade: active.releaseGrade === true,
      hardened: active.releaseGrade === true,
      alternatives: {
        microvm: { available: microvm.available === true, releaseGrade: microvm.releaseGrade === true, blockers: microvm.blockers || [] },
        windowsSandbox: { available: windows.available === true, releaseGrade: windows.releaseGrade === true, blockers: windows.blockers || [] },
      },
    };
  }

  async runContainmentSelfTest() {
    const order = this.prefer === 'microvm' ? ['microvm', 'windows-sandbox'] : ['windows-sandbox', 'microvm'];
    const failures = [];
    for (const name of order) {
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
    if (!this._active) {
      const containment = await this.runContainmentSelfTest();
      if (!containment.ok) return containment;
    }
    const backend = this._backend(this._active);
    const result = await backend.runIsolationSelfTest();
    if (result && result.ok === true) return { ...result, backend: this._active };

    const failedBackend = this._active;
    const fallback = failedBackend === 'microvm' ? 'windows-sandbox' : 'microvm';
    const fallbackBackend = this._backend(fallback);
    const fallbackContainment = await fallbackBackend.runContainmentSelfTest();
    if (!fallbackContainment || fallbackContainment.ok !== true) {
      this._active = null;
      return {
        ok: false,
        code: 'NO_ISOLATION_BACKEND_ISOLATION_CERTIFIED',
        failures: [
          { backend: failedBackend, code: result && result.code ? result.code : 'ISOLATION_SELF_TEST_FAILED' },
          { backend: fallback, code: fallbackContainment && fallbackContainment.code ? fallbackContainment.code : 'CONTAINMENT_SELF_TEST_FAILED' },
        ],
      };
    }
    const fallbackIsolation = await fallbackBackend.runIsolationSelfTest();
    if (fallbackIsolation && fallbackIsolation.ok === true) {
      this._active = fallback;
      return { ...fallbackIsolation, backend: fallback };
    }
    this._active = null;
    return {
      ok: false,
      code: 'NO_ISOLATION_BACKEND_ISOLATION_CERTIFIED',
      failures: [
        { backend: failedBackend, code: result && result.code ? result.code : 'ISOLATION_SELF_TEST_FAILED' },
        { backend: fallback, code: fallbackIsolation && fallbackIsolation.code ? fallbackIsolation.code : 'ISOLATION_SELF_TEST_FAILED' },
      ],
    };
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

module.exports = { IsolationBackendRouter };
