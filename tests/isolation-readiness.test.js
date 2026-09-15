'use strict';

const assert = require('assert');
const path = require('path');
const {
  READINESS_SCHEMA_VERSION,
  loadMxcAttestation,
  validateMxcAttestation,
  verifyAttestedHarnessBlobs,
  evaluateIsolationReadiness,
} = require('../desktop-app/sandbox/isolation-readiness.js');

const repoRoot = path.resolve(__dirname, '..');
const attestation = loadMxcAttestation();
const evidence = validateMxcAttestation(attestation);
assert.equal(evidence.ok, true, JSON.stringify(evidence, null, 2));
assert.equal(evidence.isolationTier, 'appcontainer-dacl');
assert.equal(evidence.syntheticOnly, true);
assert.equal(evidence.untrustedExecutionCertified, false);
assert.equal(evidence.authoritativeForProBehavioralRelease, false);

const sourceIdentity = verifyAttestedHarnessBlobs(repoRoot, attestation);
assert.equal(sourceIdentity.ok, true, JSON.stringify(sourceIdentity, null, 2));
assert(sourceIdentity.files.length >= 3);
assert(sourceIdentity.files.every(file => file.match === true));

// A release artifact must not depend on the CI machine having a hardware/OS
// capability that is deliberately self-certified on each end-user host.
const pendingController = {
  releaseReady: false,
  windowsSandbox: { releaseGrade: false },
};
const pending = evaluateIsolationReadiness({
  embeddedChecksPassed: true,
  controllerSelfTest: pendingController,
  mxcAttestation: attestation,
});
assert.equal(pending.schemaVersion, READINESS_SCHEMA_VERSION);
assert.equal(pending.engineeringReady, true);
assert.equal(pending.productImplementationReady, true);
assert.equal(pending.productReadinessPercent, 100);
assert.equal(pending.productReleaseReady, true);
assert.equal(pending.artifactReleaseReady, true);
assert.equal(pending.fullProductReleaseReady, true);
assert.equal(pending.releaseReady, true);
assert.equal(pending.deployableReleaseReady, true);
assert.equal(pending.deployableReleaseProfile, 'standard-plus-pro-runtime-gated');
assert.deepEqual(pending.deployableBlockers, []);

assert.equal(pending.mxcProcessContainer.validated, true);
assert.equal(pending.mxcProcessContainer.syntheticOnly, true);
assert.equal(pending.mxcProcessContainer.untrustedExecutionCertified, false);
assert.equal(pending.mxcProcessContainer.authoritativeForProBehavioralRelease, false);

// Product implementation is ready, but the current host still cannot execute
// sandbox-dependent paths until it passes the real local acceptance test.
assert.equal(pending.windowsSandboxCertified, false);
assert.equal(pending.runtimeCapabilitiesReadyOnCurrentHost, false);
assert.equal(pending.proBehavioralSandboxReady, false);
assert.equal(pending.plusSandboxEscalationReady, false);
assert.equal(pending.runtimeSelfCertification.hostSpecific, true);
assert.equal(pending.runtimeSelfCertification.failClosed, true);
assert.equal(pending.runtimeSelfCertification.currentHostCertified, false);
assert.equal(pending.runtimeSelfCertification.requiredForUntrustedBehavioralExecution, true);
assert.equal(pending.runtimeSelfCertification.productReleaseBlockedByCurrentHostCapability, false);
assert(pending.runtimeBlockers.includes('windows_sandbox_runtime_certification_pending_on_current_host'));
assert(pending.lockedCapabilities.includes('plus-sandbox-escalation'));
assert(pending.lockedCapabilities.includes('pro-behavioral-sandbox'));

for (const plan of ['standard', 'plus', 'pro']) {
  assert.equal(pending.releaseProfiles[plan].implementationReady, true, `${plan} implementation must be ready`);
  assert.equal(pending.releaseProfiles[plan].releaseReady, true, `${plan} code/profile must be release-ready`);
  assert.equal(pending.releaseProfiles[plan].coverage, 100, `${plan} implementation coverage must be 100%`);
}
assert.equal(pending.releaseProfiles.plus.runtimeSandboxEscalationReady, false);
assert.equal(pending.releaseProfiles.pro.runtimeBehavioralExecutionReady, false);
assert.equal(pending.scopedReadiness.standard, true);
assert.equal(pending.scopedReadiness.plus, true);
assert.equal(pending.scopedReadiness.pro, true);
assert.equal(pending.scopedReadiness.plusStaticAndReputation, true);
assert.equal(pending.scopedReadiness.plusSandboxEscalation, false);
assert.equal(pending.scopedReadiness.proBehavioralSandbox, false);
assert.equal(pending.status, 'PRODUCT_RELEASE_READY_RUNTIME_SANDBOX_SELF_CERTIFICATION_REQUIRED');
assert.deepEqual(pending.blockers, []);

// On a host that actually passes Windows Sandbox acceptance, the same release
// artifact gains the runtime capability without changing its product readiness.
const certifiedController = {
  releaseReady: true,
  windowsSandbox: { releaseGrade: true },
};
const certified = evaluateIsolationReadiness({
  embeddedChecksPassed: true,
  controllerSelfTest: certifiedController,
  mxcAttestation: attestation,
});
assert.equal(certified.engineeringReady, true);
assert.equal(certified.productReadinessPercent, 100);
assert.equal(certified.productReleaseReady, true);
assert.equal(certified.releaseReady, true);
assert.equal(certified.fullProductReleaseReady, true);
assert.equal(certified.windowsSandboxCertified, true);
assert.equal(certified.runtimeCapabilitiesReadyOnCurrentHost, true);
assert.equal(certified.runtimeSelfCertification.currentHostCertified, true);
assert.equal(certified.proBehavioralSandboxReady, true);
assert.equal(certified.plusSandboxEscalationReady, true);
assert.equal(certified.releaseProfiles.plus.runtimeSandboxEscalationReady, true);
assert.equal(certified.releaseProfiles.pro.runtimeBehavioralExecutionReady, true);
assert.deepEqual(certified.lockedCapabilities, []);
assert.deepEqual(certified.runtimeBlockers, []);
assert.equal(certified.status, 'PRODUCT_RELEASE_READY_ALL_RUNTIME_CAPABILITIES_AVAILABLE_ON_CURRENT_HOST');

// Synthetic MXC evidence is still not allowed to pretend it certified untrusted
// execution. Invalid attestation must make the product release fail closed.
const unsafeAttestation = JSON.parse(JSON.stringify(attestation));
unsafeAttestation.scope.untrustedExecutionCertified = true;
const unsafeEvidence = validateMxcAttestation(unsafeAttestation);
assert.equal(unsafeEvidence.ok, false, 'attestation must fail if it tries to claim untrusted-execution certification');
const unsafeReadiness = evaluateIsolationReadiness({
  embeddedChecksPassed: true,
  controllerSelfTest: certifiedController,
  mxcAttestation: unsafeAttestation,
});
assert.equal(unsafeReadiness.engineeringReady, false);
assert.equal(unsafeReadiness.productImplementationReady, false);
assert.equal(unsafeReadiness.productReadinessPercent, 0);
assert.equal(unsafeReadiness.productReleaseReady, false);
assert.equal(unsafeReadiness.deployableReleaseReady, false);
assert.equal(unsafeReadiness.releaseReady, false);
assert.equal(unsafeReadiness.deployableReleaseProfile, 'none');
assert(unsafeReadiness.blockers.includes('MXC_ATTESTATION_CONTRACT_FAILED'));

console.log('✓ Isolation readiness: product release is 100% when engineering acceptance passes; real Windows Sandbox remains a per-host fail-closed runtime capability');
