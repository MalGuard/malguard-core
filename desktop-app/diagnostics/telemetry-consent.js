'use strict';

// The only permission gate for installation diagnostics. Unknown state is denied.
class TelemetryConsent {
  constructor(readSettings) { this.readSettings = readSettings; this.controllers = new Set(); this.revoked = false; }
  canSendDiagnostics() {
    try {
      const d = this.readSettings().diagnostics;
      return !this.revoked && d?.enabled === true && typeof d.consentUpdatedAt === 'string' && !d.deletionPending;
    } catch (_) { return false; }
  }
  cancel() { for (const c of this.controllers) c.abort(); this.controllers.clear(); }
  async send(fetchImpl, url, options) {
    if (!this.canSendDiagnostics()) return { ok: false, skipped: true };
    const controller = new AbortController();
    this.controllers.add(controller);
    const timer = setTimeout(() => controller.abort(), 5000);
    try {
      // No await between this final gate and dispatch.
      if (!this.canSendDiagnostics()) return { ok: false, skipped: true };
      return await fetchImpl(url, { ...options, signal: controller.signal, redirect: 'error' });
    } finally { clearTimeout(timer); this.controllers.delete(controller); }
  }
}
module.exports = { TelemetryConsent };
