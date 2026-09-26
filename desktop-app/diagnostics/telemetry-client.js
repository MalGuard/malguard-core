'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { TelemetryConsent } = require('./telemetry-consent.js');
const { buildTelemetryPayload } = require('./telemetry-payload.js');

class TelemetryClient {
  constructor({ readSettings, saveSettings, settingsFile, version, build, fetchImpl = globalThis.fetch, device, endpoint = process.env.MALGUARD_DIAGNOSTICS_ENDPOINT || '' }) {
    Object.assign(this, { readSettings, saveSettings, settingsFile, version, build, fetchImpl, device, endpoint });
    this.consent = new TelemetryConsent(readSettings);
    this.generation = 0; this.timer = null; this.registered = false; this.snapshot = null; this.lastResult = 'idle';
    this.credentialFile = path.join(path.dirname(settingsFile), 'diagnostics-credential.json');
  }
  async preview(event = 'register') {
    const settings = this.readSettings();
    if (event !== 'register') return buildTelemetryPayload({ settings, version:this.version, build:this.build, event });
    const generation = this.generation;
    if (!this.snapshot) {
      const payload = await buildTelemetryPayload({ settings, version:this.version, build:this.build, device:this.device });
      if (generation !== this.generation) return this.preview(event);
      this.snapshot = payload;
    }
    return structuredClone(this.snapshot);
  }
  credential(create = false) {
    const id = this.readSettings().diagnostics.installationId;
    try {
      const c = JSON.parse(fs.readFileSync(this.credentialFile, 'utf8'));
      if (c.installationId === id && /^[a-f0-9]{64}$/.test(c.token)) return c.token;
    } catch (_) { /* Missing or invalid credential does not authorize any remote operation. */ }
    if (!create) return null;
    const token = crypto.randomBytes(32).toString('hex');
    fs.mkdirSync(path.dirname(this.credentialFile), {recursive:true, mode:0o700});
    const tmp = `${this.credentialFile}.${crypto.randomUUID()}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify({installationId:id,token}), {flag:'wx',mode:0o600});
    fs.renameSync(tmp,this.credentialFile);
    return token;
  }
  url(event) {
    const url = new URL(this.endpoint);
    if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.port && url.port !== '443') throw new Error('invalid-endpoint');
    return `${url.origin}${url.pathname.replace(/\/$/,'')}/${event}`;
  }
  stop() { this.generation++; this.snapshot=null; this.registered=false; clearInterval(this.timer); this.timer=null; this.consent.cancel(); }
  async send(event = 'register') {
    if (!this.consent.canSendDiagnostics()) return {ok:true,sent:false,reason:'consent-required'};
    const generation = this.generation;
    try {
      const url = this.url(event);
      const token = this.credential(true);
      const payload = await this.preview(event);
      if (generation !== this.generation || !this.consent.canSendDiagnostics()) return {ok:true,sent:false};
      const response = await this.consent.send(this.fetchImpl, url, {method:'POST', headers:{'content-type':'application/json',authorization:`Bearer ${token}`}, body:JSON.stringify(payload)});
      if (!response.ok) { this.lastResult='upload-unavailable'; return {ok:false,sent:false,reason:this.lastResult}; }
      if (generation !== this.generation || !this.consent.canSendDiagnostics()) return {ok:true,sent:false};
      // Keep concurrent protection settings; only the upload timestamp is changed.
      const current = this.readSettings();
      this.saveSettings({...current, diagnostics:{...current.diagnostics,lastUploadAt:new Date().toISOString()}});
      this.registered=true; this.lastResult='uploaded';
      return {ok:true,sent:true};
    } catch (_) { this.lastResult='upload-unavailable'; return {ok:false,sent:false,reason:this.lastResult}; }
  }
  start() {
    this.stop();
    this.consent.revoked = false;
    if (!this.consent.canSendDiagnostics()) return;
    void this.send();
    // Daily while the application is running, no background process or location tracking.
    this.timer=setInterval(() => { void this.send(this.registered ? 'heartbeat' : 'register'); },24*60*60*1000);
    this.timer.unref?.();
  }
  async disableAndDelete() {
    this.consent.revoked = true;
    this.stop();
    const current=this.readSettings();
    this.saveSettings({...current,diagnostics:{...current.diagnostics,enabled:false,shareRegion:false,consentUpdatedAt:new Date().toISOString(),deletionPending:true}});
    // Explicit privacy-control request, never an analytics upload. No automatic retries.
    try {
      const token=this.credential();
      if (token) {
        const response=await this.fetchImpl(this.url('unregister'),{method:'POST',redirect:'error',signal:AbortSignal.timeout(5000),headers:{'content-type':'application/json',authorization:`Bearer ${token}`},body:JSON.stringify({installationId:current.diagnostics.installationId})});
        if (!response.ok) throw new Error('delete-unavailable');
      }
      const latest=this.readSettings();
      this.saveSettings({...latest,diagnostics:{...latest.diagnostics,installationId:token ? crypto.randomUUID() : latest.diagnostics.installationId,deletionPending:false,lastUploadAt:null,country:null,region:null}});
      fs.rmSync(this.credentialFile,{force:true}); this.lastResult='deleted';
      return {ok:true,deleted:true};
    } catch (_) { this.lastResult='deletion-pending'; return {ok:false,deleted:false,reason:'deletion-pending'}; }
  }
}
module.exports={TelemetryClient};
