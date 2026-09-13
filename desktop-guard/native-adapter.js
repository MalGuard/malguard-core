'use strict';

class NativeGuardAdapter {
  constructor() {
    this.version = '0.1.0';
  }

  async startWatching() {
    const error = new Error('Native filesystem monitoring is not implemented in the browser core. A signed desktop companion is required.');
    error.code = 'NATIVE_GUARD_NOT_IMPLEMENTED';
    throw error;
  }

  async stopWatching() { return { ok: true, active: false }; }

  async quarantine() {
    const error = new Error('Native quarantine requires the desktop companion.');
    error.code = 'NATIVE_QUARANTINE_NOT_IMPLEMENTED';
    throw error;
  }
}

if (typeof module !== 'undefined' && module.exports) module.exports = { NativeGuardAdapter };
if (typeof globalThis !== 'undefined') globalThis.MalGuardNativeGuardAdapter = NativeGuardAdapter;
