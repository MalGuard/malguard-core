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
assert.equal(pending.mxcProcessContainer.validated, true);
assert.equal(pending.mxcProcessContainer.syntheticOnly, true);
assert.equal(pending.mxcProcessContainer.untrustedExecutionCertified, false);
assert.equal(pending.mxcProcessContainer.authoritativeForProBehavioralRelease, false);
assert.equal(pending.windowsSandboxCertified, false);
assert.equal(pending.proBehavioralSandboxReady, false);
assert.equal(pending.scopedReadiness.standard, true);
assert.equal(pending.scopedReadiness.plusStaticAndReputation, true);
assert.equal(pending.scopedReadiness.plusSandboxEscalation, false);
assert.equal(pending.scopedReadiness.proBehavioralSandbox, false);
assert.equal(pending.releaseProfiles.standard.ready, true);
assert.equal(pending.releaseProfiles.standard.coverage, 100);
assert.equal(pending.releaseProfiles.plus.ready, false);
assert.equal(pending.releaseProfiles.pro.ready, false);
assert.equal(pending.deployableReleaseReady, true);
assert.equal(pending.deployableReleaseProfile, 'standard-only');
assert.deepEqual(pending.deployableBlockers, []);
assert(pending.lockedCapabilities.includes('plus-sandbox-escalation'));
assert(pending.lockedCapabilities.includes('pro-behavioral-sandbox'));
assert.equal(pending.releaseReady, false, 'MXC synthetic evidence must never unlock full behavioral release');
assert.equal(pending.fullProductReleaseReady, false);
assert.equal(pending.status, 'STANDARD_RELEASE_READY_PLUS_PRO_LOCKED');
assert(pending.blockers.includes('windows_sandbox_runtime_certification_pending'));

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
assert.equal(certified.windowsSandboxCertified, true);
assert.equal(certified.proBehavioralSandboxReady, true);
assert.equal(certified.releaseReady, true);
assert.equal(certified.fullProductReleaseReady, true);
assert.equal(certified.deployableReleaseReady, true);
assert.equal(certified.deployableReleaseProfile, 'standard-plus-pro');
assert.equal(certified.releaseProfiles.standard.ready, true);
assert.equal(certified.releaseProfiles.plus.ready, true);
assert.equal(certified.releaseProfiles.pro.ready, true);
assert.deepEqual(certified.lockedCapabilities, []);
assert.equal(certified.status, 'FULL_RELEASE_READY');

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
assert.equal(unsafeReadiness.deployableReleaseReady, false);
assert.equal(unsafeReadiness.releaseReady, false);
assert.equal(unsafeReadiness.deployableReleaseProfile, 'none');

console.log('✓ Isolation readiness: Standard can be fully release-ready while Plus/Pro remain locked until real Windows Sandbox certification');
