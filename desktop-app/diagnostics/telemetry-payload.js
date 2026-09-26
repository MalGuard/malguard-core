'use strict';
const os = require('os');
const { collectWindowsDevice } = require('./windows-device.js');
const DEVICE_FIELDS = ['deviceManufacturer','deviceModel','cpuModel','cpuCores','cpuThreads','ramBytes','gpuModel','windowsEdition','windowsVersion','windowsBuild','architecture'];
const CAPABILITY_FIELDS = ['windowsSandboxAvailable','virtualizationAvailable','defenderAvailable','yaraXAvailable','capaAvailable','malguardAiAvailable'];

async function buildTelemetryPayload({ settings, version, build = null, device = collectWindowsDevice, capabilities = {}, event = 'register' }) {
  const d = settings.diagnostics;
  const base = { installationId: d.installationId, diagnosticsConsent: true, malguardVersion: version };
  if (event === 'heartbeat') return base;
  const approved = {};
  for (const key of CAPABILITY_FIELDS) approved[key] = typeof capabilities[key] === 'boolean' ? capabilities[key] : null;
  if (event === 'engine-status') return { ...base, capabilities: approved };
  const inventory = d.enabled ? await device() : {};
  const fields = {};
  for (const key of DEVICE_FIELDS) fields[key] = inventory[key] ?? null;
  return { ...base, identityType: 'anonymous', malguardBuild: build, ...fields,
    appLanguage: Intl.DateTimeFormat().resolvedOptions().locale,
    installStatus: 'unknown', firstLaunchStatus: 'succeeded',
    regionConsent: d.shareRegion === true,
    // Region is optionally entered by the user, never inferred from IP/location APIs.
    country: d.shareRegion ? d.country : null,
    region: d.shareRegion ? d.region : null,
    capabilities: approved };
}
module.exports = { buildTelemetryPayload, DEVICE_FIELDS, CAPABILITY_FIELDS };
