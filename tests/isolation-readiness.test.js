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
assert.equal(pending.releaseReady, false, 'MXC synthetic evidence must never unlock full behavioral release');
assert.equal(pending.status, 'ENGINEERING_READY_PRO_SANDBOX_PENDING');
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
assert.equal(unsafeReadiness.releaseReady, false);

console.log('✓ Isolation readiness: MXC live evidence is scoped, source-pinned, and cannot bypass Pro Windows Sandbox certification');
