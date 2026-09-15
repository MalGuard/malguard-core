'use strict';

const AGENT_VERSION = '0.2.0';
const PROTOCOL_VERSION = '1.0.0';
const GUARD_CONTRACT_VERSION = '0.2.0';

const CAPABILITIES = Object.freeze([
  'user_space_watch',
  'baseline_existing_file_scan',
  'watcher_health_reconciliation',
  'sha256_revalidation',
  'quarantine',
  'restore',
  'managed_install',
  'incident_attribution',
]);

const LIMITATIONS = Object.freeze([
  'no_kernel_minifilter',
  'no_preload_guarantee_for_out_of_band_files',
  'not_a_windows_service_yet',
]);

function createAgentHello() {
  return Object.freeze({
    product: 'MalGuard Desktop Guard',
    agentVersion: AGENT_VERSION,
    protocolVersion: PROTOCOL_VERSION,
    guardContractVersion: GUARD_CONTRACT_VERSION,
    capabilities: [...CAPABILITIES],
    limitations: [...LIMITATIONS],
  });
}

function validateCoreHello(hello) {
  if (!hello || typeof hello !== 'object') return { ok: false, error: 'CORE_HELLO_REQUIRED' };
  if (hello.protocolVersion !== PROTOCOL_VERSION) return { ok: false, error: 'PROTOCOL_VERSION_MISMATCH' };
  if (hello.guardContractVersion !== GUARD_CONTRACT_VERSION) return { ok: false, error: 'GUARD_CONTRACT_VERSION_MISMATCH' };
  return { ok: true };
}

module.exports = {
  AGENT_VERSION,
  PROTOCOL_VERSION,
  GUARD_CONTRACT_VERSION,
  CAPABILITIES,
  LIMITATIONS,
  createAgentHello,
  validateCoreHello,
};
