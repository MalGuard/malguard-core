'use strict';

const { EmbeddedValidationLab } = require('../desktop-app/sandbox/embedded-validation-lab.js');

function requireTrue(condition, message) {
  if (!condition) {
    const error = new Error(message);
    error.code = 'PRODUCT_READINESS_GATE_FAILED';
    throw error;
  }
}

(async () => {
  const report = await new EmbeddedValidationLab({ timeoutMs: 5000, memoryMb: 48 }).run();

  requireTrue(report && report.kind === 'malguard-embedded-validation-lab', 'embedded validation report is missing or invalid');
  requireTrue(report.safety && report.safety.syntheticFixturesOnly === true, 'readiness gate must use synthetic fixtures only');
  requireTrue(report.safety.untrustedSamplesExecuted === false, 'readiness gate must not execute untrusted samples');
  requireTrue(report.safety.malwareDownloaded === false, 'readiness gate must not download malware');
  requireTrue(report.safety.releaseGateBypassed === false, 'runtime release gate must not be bypassed');
  requireTrue(report.safety.realWindowsSandboxClaimedByVirtualLab === false, 'virtual validation must not claim real Windows Sandbox execution');
  requireTrue(report.safety.runtimeSandboxGateStillEnforced === true, 'runtime Sandbox gate must remain enforced');

  requireTrue(report.engineeringValidationPercent === 100, `engineering validation is ${report.engineeringValidationPercent}% instead of 100%`);
  requireTrue(report.engineeringReady === true, 'engineering readiness is false');
  requireTrue(report.productImplementationReady === true, 'product implementation readiness is false');
  requireTrue(report.productReadinessPercent === 100, `product readiness is ${report.productReadinessPercent}% instead of 100%`);
  requireTrue(report.productReleaseReady === true, 'product release readiness is false');
  requireTrue(report.artifactReleaseReady === true, 'release artifact readiness is false');
  requireTrue(report.fullProductReleaseReady === true, 'full product release readiness is false');
  requireTrue(report.releaseReady === true, 'releaseReady compatibility field is false');
  requireTrue(report.deployableReleaseReady === true, 'deployable release readiness is false');
  requireTrue(report.deployableReleaseProfile === 'standard-plus-pro-runtime-gated', 'unexpected deployable release profile');

  for (const plan of ['standard', 'plus', 'pro']) {
    const profile = report.releaseProfiles && report.releaseProfiles[plan];
    requireTrue(profile && profile.implementationReady === true, `${plan} implementation is not ready`);
    requireTrue(profile.releaseReady === true, `${plan} release profile is not ready`);
    requireTrue(profile.coverage === 100, `${plan} release profile coverage is not 100%`);
  }

  requireTrue(report.virtualWindowsLab && report.virtualWindowsLab.ok === true, 'Virtual Windows Validation Lab failed');
  requireTrue(report.virtualWindowsLab.coveragePercent === 100, 'Virtual Windows Validation Lab coverage is not 100%');
  requireTrue(report.mxcProcessContainer && report.mxcProcessContainer.validated === true, 'MXC ProcessContainer engineering evidence is not validated');
  requireTrue(report.mxcProcessContainer.untrustedExecutionCertified === false, 'MXC must not claim untrusted-execution certification');

  const selfCert = report.runtimeSelfCertification;
  requireTrue(selfCert && selfCert.hostSpecific === true, 'runtime Sandbox certification must be host-specific');
  requireTrue(selfCert.failClosed === true, 'runtime Sandbox certification must fail closed');
  requireTrue(selfCert.requiredForUntrustedBehavioralExecution === true, 'runtime Sandbox certification must remain mandatory for untrusted behavioral execution');
  requireTrue(selfCert.currentHostCertified === report.windowsSandboxCertified, 'current-host runtime certification state is inconsistent');
  requireTrue(report.proBehavioralSandboxReady === report.windowsSandboxCertified, 'Pro runtime gate is inconsistent');
  requireTrue(report.plusSandboxEscalationReady === report.windowsSandboxCertified, 'Plus runtime gate is inconsistent');

  if (!report.windowsSandboxCertified) {
    requireTrue(report.lockedCapabilities.includes('plus-sandbox-escalation'), 'Plus Sandbox escalation must be locked on an uncertified host');
    requireTrue(report.lockedCapabilities.includes('pro-behavioral-sandbox'), 'Pro behavioral Sandbox must be locked on an uncertified host');
    requireTrue(report.runtimeBlockers.includes('windows_sandbox_runtime_certification_pending_on_current_host'), 'current-host runtime blocker is missing');
  }

  const summary = {
    ok: true,
    productReadinessPercent: report.productReadinessPercent,
    engineeringValidationPercent: report.engineeringValidationPercent,
    productReleaseReady: report.productReleaseReady,
    deployableReleaseProfile: report.deployableReleaseProfile,
    virtualWindowsCoveragePercent: report.virtualWindowsLab.coveragePercent,
    mxcValidated: report.mxcProcessContainer.validated,
    windowsSandboxCertifiedOnCurrentHost: report.windowsSandboxCertified,
    runtimeCapabilitiesReadyOnCurrentHost: report.runtimeCapabilitiesReadyOnCurrentHost,
    lockedCapabilities: report.lockedCapabilities,
    status: report.status,
    safety: report.safety,
  };
  console.log(JSON.stringify(summary, null, 2));
  console.log('✓ Product readiness gate: 100% product/release implementation PASS; host-specific Windows Sandbox runtime remains independently self-certified and fail-closed');
})().catch(error => {
  console.error(`✗ Product readiness gate: ${error.code || 'ERROR'}: ${error.message}`);
  process.exit(1);
});
