'use strict';

const assert = require('assert');
const { EmbeddedValidationLab, LAB_SCHEMA_VERSION } = require('../desktop-app/sandbox/embedded-validation-lab.js');

(async () => {
  const lab = new EmbeddedValidationLab({ timeoutMs: 5000, memoryMb: 48 });
  const report = await lab.run();

  assert.equal(report.schemaVersion, LAB_SCHEMA_VERSION);
  assert.equal(report.kind, 'malguard-embedded-validation-lab');
  assert.equal(report.safety.syntheticFixturesOnly, true);
  assert.equal(report.safety.untrustedSamplesExecuted, false);
  assert.equal(report.safety.malwareDownloaded, false);
  assert.equal(report.safety.releaseGateBypassed, false);
  assert.equal(report.safety.realWindowsSandboxClaimedByVirtualLab, false);
  assert.equal(report.safety.runtimeSandboxGateStillEnforced, true);

  assert.equal(report.engineeringValidationPercent, 100, JSON.stringify(report, null, 2));
  assert.equal(report.engineeringReady, true, JSON.stringify(report, null, 2));
  assert.equal(report.productImplementationReady, true, JSON.stringify(report, null, 2));
  assert.equal(report.productReadinessPercent, 100, JSON.stringify(report, null, 2));
  assert.equal(report.productReleaseReady, true, JSON.stringify(report, null, 2));
  assert.equal(report.artifactReleaseReady, true);
  assert.equal(report.deployableReleaseReady, true);
  assert.equal(report.fullProductReleaseReady, true);
  assert.equal(report.releaseReady, true);
  assert.equal(report.deployableReleaseProfile, 'standard-plus-pro-runtime-gated');

  for (const plan of ['standard', 'plus', 'pro']) {
    assert.equal(report.releaseProfiles[plan].implementationReady, true);
    assert.equal(report.releaseProfiles[plan].releaseReady, true);
    assert.equal(report.releaseProfiles[plan].coverage, 100);
  }

  assert.equal(report.virtualWindowsLab.ok, true, JSON.stringify(report.virtualWindowsLab, null, 2));
  assert.equal(report.virtualWindowsLab.coveragePercent, 100, JSON.stringify(report.virtualWindowsLab, null, 2));
  assert.equal(report.virtualWindowsLab.safety.realWindowsSandboxClaimed, false);
  assert.equal(report.mxcProcessContainer.validated, true, JSON.stringify(report.mxcProcessContainer, null, 2));
  assert.equal(report.mxcProcessContainer.syntheticOnly, true);
  assert.equal(report.mxcProcessContainer.untrustedExecutionCertified, false);
  assert.equal(report.mxcProcessContainer.authoritativeForProBehavioralRelease, false);

  const names = new Set(report.checks.map(item => item.name));
  for (const required of [
    'synthetic_sample_preflight',
    'telemetry_accepts_valid_synthetic_contract',
    'telemetry_rejects_session_confusion',
    'telemetry_rejects_invalid_network_policy',
    'windows_sandbox_policy_contract',
    'release_path_fails_closed_without_accepted_backend',
    'local_process_isolation_probe',
    'virtual_windows_contract_lab',
  ]) {
    assert(names.has(required), `missing embedded validation check: ${required}`);
  }
  assert(report.checks.every(item => item.ok === true), JSON.stringify(report.checks, null, 2));

  assert.equal(report.runtimeSelfCertification.hostSpecific, true);
  assert.equal(report.runtimeSelfCertification.failClosed, true);
  assert.equal(report.runtimeSelfCertification.requiredForUntrustedBehavioralExecution, true);
  assert.equal(report.runtimeSelfCertification.currentHostCertified, report.windowsSandboxCertified);
  assert.equal(report.proBehavioralSandboxReady, report.windowsSandboxCertified);
  assert.equal(report.plusSandboxEscalationReady, report.windowsSandboxCertified);
  assert.equal(report.runtimeCapabilitiesReadyOnCurrentHost, report.windowsSandboxCertified);

  if (report.windowsSandboxCertified) {
    assert.equal(report.status, 'PRODUCT_RELEASE_READY_ALL_RUNTIME_CAPABILITIES_AVAILABLE_ON_CURRENT_HOST');
    assert.equal(report.windowsSandbox.releaseGrade, true);
    assert.equal(report.releaseProfiles.plus.runtimeSandboxEscalationReady, true);
    assert.equal(report.releaseProfiles.pro.runtimeBehavioralExecutionReady, true);
    assert.equal(report.scopedReadiness.plusSandboxEscalation, true);
    assert.equal(report.scopedReadiness.proBehavioralSandbox, true);
    assert.deepEqual(report.lockedCapabilities, []);
    assert.deepEqual(report.runtimeBlockers, []);
  } else {
    assert.equal(report.status, 'PRODUCT_RELEASE_READY_RUNTIME_SANDBOX_SELF_CERTIFICATION_REQUIRED');
    assert.equal(report.releaseProfiles.plus.runtimeSandboxEscalationReady, false);
    assert.equal(report.releaseProfiles.pro.runtimeBehavioralExecutionReady, false);
    assert.equal(report.scopedReadiness.plusSandboxEscalation, false);
    assert.equal(report.scopedReadiness.proBehavioralSandbox, false);
    assert(report.lockedCapabilities.includes('plus-sandbox-escalation'));
    assert(report.lockedCapabilities.includes('pro-behavioral-sandbox'));
    assert(report.runtimeBlockers.includes('windows_sandbox_runtime_certification_pending_on_current_host'));
  }

  console.log(`✓ Embedded Validation Lab: engineering=${report.engineeringValidationPercent}%; product=${report.productReadinessPercent}%; releaseReady=${report.productReleaseReady}; runtime Windows Sandbox certified=${report.windowsSandboxCertified}`);
})().catch(error => {
  console.error(error.stack || error);
  process.exit(1);
});
