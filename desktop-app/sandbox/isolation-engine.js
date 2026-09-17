'use strict';

const ISOLATION_ENGINE_VERSION = '1.0.0';

const WINDOWS_GUEST_EXTENSIONS = new Set([
  '.exe', '.com', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js',
]);

class IsolationEngine {
  constructor({ windowsBackend = null } = {}) {
    this.windowsBackend = windowsBackend;
  }

  coreCapabilities() {
    return {
      engine: 'malguard-isolation-engine',
      version: ISOLATION_ENGINE_VERSION,
      coreReady: true,
      hostExecutionAllowed: false,
      policy: {
        untrustedExecutionOnHost: 'forbidden',
        failClosed: true,
        inputMapping: 'read-only',
        guestLifetime: 'ephemeral',
        networkDefault: 'disabled',
        clipboard: 'disabled',
      },
    };
  }

  requiresWindowsGuest(preflight) {
    return !!(preflight && WINDOWS_GUEST_EXTENSIONS.has(String(preflight.extension || '').toLowerCase()));
  }

  async runtimeCapabilities(certification = null) {
    const core = this.coreCapabilities();
    let windows = {
      backend: 'windows-sandbox',
      available: false,
      releaseGrade: false,
    };
    if (this.windowsBackend && typeof this.windowsBackend.capabilities === 'function') {
      try {
        windows = await this.windowsBackend.capabilities();
      } catch (_) {}
    }

    const behavioralExecutionReady = !!(
      certification &&
      certification.executionCertified === true &&
      windows &&
      windows.releaseGrade === true
    );

    return {
      ...core,
      behavioralExecutionReady,
      windowsGuestProvider: {
        id: 'windows-sandbox',
        available: windows.available === true,
        releaseGrade: windows.releaseGrade === true,
        executionCertified: !!(certification && certification.executionCertified === true),
      },
      note: behavioralExecutionReady
        ? 'Real Windows guest execution is available through the certified provider.'
        : 'Isolation core is healthy, but real Windows guest execution is not available on this host.',
    };
  }

  async selectProvider(preflight, certification = null) {
    if (!this.requiresWindowsGuest(preflight)) {
      return { ok: false, code: 'ISOLATION_GUEST_TYPE_UNSUPPORTED', provider: null };
    }
    const runtime = await this.runtimeCapabilities(certification);
    if (!runtime.behavioralExecutionReady) {
      return {
        ok: false,
        code: 'WINDOWS_GUEST_EXECUTION_PROVIDER_UNAVAILABLE',
        provider: null,
        runtime,
      };
    }
    return {
      ok: true,
      code: 'ISOLATION_PROVIDER_SELECTED',
      provider: 'windows-sandbox',
      runtime,
    };
  }
}

module.exports = { IsolationEngine, ISOLATION_ENGINE_VERSION, WINDOWS_GUEST_EXTENSIONS };
