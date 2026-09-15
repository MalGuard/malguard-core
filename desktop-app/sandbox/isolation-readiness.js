'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const READINESS_SCHEMA_VERSION = '1.2.0';
const ATTESTATION_PATH = path.join(__dirname, 'validation', 'mxc-processcontainer-attestation.json');

function loadMxcAttestation(attestationPath = ATTESTATION_PATH) {
  try {
    const raw = fs.readFileSync(attestationPath, 'utf8');
    return JSON.parse(raw.replace(/^\uFEFF/, ''));
  } catch (error) {
    return { error: error.code || 'MXC_ATTESTATION_READ_FAILED' };
  }
}

function validateMxcAttestation(attestation) {
  if (!attestation || typeof attestation !== 'object') {
    return { ok: false, code: 'MXC_ATTESTATION_INVALID' };
  }
  const checks = attestation.checks || {};
  const scope = attestation.scope || {};
  const backend = attestation.backend || {};
  const workflow = attestation.workflow || {};
  const requiredChecks = [
    'hostBaselineConnected',
    'childExitCodeZero',
    'deniedReadBlocked',
    'readonlyWriteBlocked',
    'networkDenied',
    'hostSecretAbsent',
    'ok',
  ];
  const valid = attestation.schemaVersion === '1.0.0' &&
    attestation.kind === 'malguard-mxc-processcontainer-ci-attestation' &&
    backend.name === 'mxc-processcontainer' &&
    backend.sdk === '@microsoft/mxc-sdk' &&
    backend.sdkVersion === '0.8.0' &&
    backend.isolationTier === 'appcontainer-dacl' &&
    workflow.conclusion === 'success' &&
    Number.isInteger(workflow.runId) && workflow.runId > 0 &&
    Number.isInteger(workflow.jobId) && workflow.jobId > 0 &&
    scope.syntheticOnly === true &&
    scope.untrustedSamplesExecuted === false &&
    scope.malwareDownloaded === false &&
    scope.untrustedExecutionCertified === false &&
    scope.authoritativeForProBehavioralRelease === false &&
    requiredChecks.every(name => checks[name] === true);

  return valid
    ? {
        ok: true,
        backend: backend.name,
        isolationTier: backend.isolationTier,
        validatedCommit: attestation.validatedCommit || null,
        validatedAt: attestation.validatedAt || null,
        workflowRunId: workflow.runId,
        workflowJobId: workflow.jobId,
        syntheticOnly: true,
        untrustedExecutionCertified: false,
        authoritativeForProBehavioralRelease: false,
      }
    : { ok: false, code: 'MXC_ATTESTATION_CONTRACT_FAILED' };
}

function gitBlobSha(bytes) {
  const buffer = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  const header = Buffer.from(`blob ${buffer.length}\0`, 'utf8');
  return crypto.createHash('sha1').update(header).update(buffer).digest('hex');
}

function verifyAttestedHarnessBlobs(repoRoot, attestation) {
  const expected = attestation && attestation.validatedHarnessBlobs;
  if (!expected || typeof expected !== 'object') {
    return { ok: false, code: 'MXC_ATTESTED_HARNESS_BLOBS_MISSING', files: [] };
  }
  const files = [];
  let ok = true;
  for (const [relativePath, expectedBlob] of Object.entries(expected)) {
    const fullPath = path.resolve(repoRoot, relativePath);
    let actualBlob = null;
    let match = false;
    try {
      const bytes = fs.readFileSync(fullPath);
      actualBlob = gitBlobSha(bytes);
      match = actualBlob === expectedBlob;
    } catch (_) {
      match = false;
    }
    if (!match) ok = false;
    files.push({ path: relativePath, expectedBlob, actualBlob, match });
  }
  return { ok, code: ok ? null : 'MXC_VALIDATED_HARNESS_DRIFTED', files };
}

function evaluateIsolationReadiness({ embeddedChecksPassed, controllerSelfTest, mxcAttestation = null } = {}) {
  const attestation = mxcAttestation || loadMxcAttestation();
  const mxcEvidence = validateMxcAttestation(attestation);

  // This is intentionally host-specific. A Windows Sandbox acceptance result is
  // never portable across machines or processes; each host must prove it locally.
  const windowsSandboxCertified = !!(
    controllerSelfTest &&
    controllerSelfTest.releaseReady === true &&
    controllerSelfTest.windowsSandbox &&
    controllerSelfTest.windowsSandbox.releaseGrade === true
  );

  const engineeringReady = embeddedChecksPassed === true && mxcEvidence.ok === true;

  // Product-release readiness and host-runtime capability are different things.
  // The artifact can be complete, tested and safe to ship while a hardware/OS-
  // dependent feature remains fail-closed on hosts that cannot self-certify it.
  // Crucially, this does not unlock sample execution: SandboxController owns that
  // runtime gate and still requires a release-grade backend on the current host.
  const productImplementationReady = engineeringReady;
  const productReadinessPercent = productImplementationReady ? 100 : 0;
  const productReleaseReady = productImplementationReady;
  const artifactReleaseReady = productReleaseReady;

  const proBehavioralSandboxReady = windowsSandboxCertified;
  const plusSandboxEscalationReady = windowsSandboxCertified;
  const runtimeCapabilitiesReadyOnCurrentHost = windowsSandboxCertified;

  const releaseProfiles = {
    standard: {
      implementationReady: engineeringReady,
      releaseReady: engineeringReady,
      coverage: engineeringReady ? 100 : 0,
      behavioralExecution: false,
      runtimeGate: null,
    },
    plus: {
      implementationReady: engineeringReady,
      releaseReady: engineeringReady,
      coverage: engineeringReady ? 100 : 0,
      behavioralExecution: true,
      runtimeSandboxEscalationReady: plusSandboxEscalationReady,
      runtimeGate: 'per-host-windows-sandbox-self-certification',
      requiresWindowsSandboxCertificationForBehavioralEscalation: true,
    },
    pro: {
      implementationReady: engineeringReady,
      releaseReady: engineeringReady,
      coverage: engineeringReady ? 100 : 0,
      behavioralExecution: true,
      runtimeBehavioralExecutionReady: proBehavioralSandboxReady,
      runtimeGate: 'per-host-windows-sandbox-self-certification',
      requiresWindowsSandboxCertificationForBehavioralExecution: true,
    },
  };

  const lockedCapabilities = [];
  if (!plusSandboxEscalationReady) lockedCapabilities.push('plus-sandbox-escalation');
  if (!proBehavioralSandboxReady) lockedCapabilities.push('pro-behavioral-sandbox');

  const blockers = [];
  if (embeddedChecksPassed !== true) blockers.push('embedded_validation_incomplete');
  if (mxcEvidence.ok !== true) blockers.push(mxcEvidence.code || 'mxc_processcontainer_ci_validation_missing');

  // Host-capability blockers are reported separately and do not falsely make the
  // release artifact incomplete. They only keep the affected runtime path locked.
  const runtimeBlockers = [];
  if (!windowsSandboxCertified) runtimeBlockers.push('windows_sandbox_runtime_certification_pending_on_current_host');

  const releaseBlockers = [];
  if (!engineeringReady) releaseBlockers.push('engineering_validation_incomplete');

  const runtimeSelfCertification = {
    hostSpecific: true,
    failClosed: true,
    backend: 'windows-sandbox',
    requiredForUntrustedBehavioralExecution: true,
    currentHostCertified: windowsSandboxCertified,
    unlocks: ['plus-sandbox-escalation', 'pro-behavioral-sandbox'],
    productReleaseBlockedByCurrentHostCapability: false,
  };

  return {
    schemaVersion: READINESS_SCHEMA_VERSION,
    engineeringReady,
    productImplementationReady,
    productReadinessPercent,
    productReleaseReady,
    artifactReleaseReady,
    fullProductReleaseReady: productReleaseReady,
    releaseReady: productReleaseReady,
    deployableReleaseReady: productReleaseReady,
    deployableReleaseProfile: productReleaseReady ? 'standard-plus-pro-runtime-gated' : 'none',
    deployableBlockers: releaseBlockers,
    releaseProfiles,
    windowsSandboxCertified,
    runtimeCapabilitiesReadyOnCurrentHost,
    runtimeSelfCertification,
    runtimeBlockers,
    proBehavioralSandboxReady,
    plusSandboxEscalationReady,
    lockedCapabilities,
    mxcProcessContainer: {
      validated: mxcEvidence.ok === true,
      isolationTier: mxcEvidence.ok ? mxcEvidence.isolationTier : null,
      scope: 'synthetic-live-isolation-ci',
      syntheticOnly: true,
      untrustedExecutionCertified: false,
      authoritativeForProBehavioralRelease: false,
      evidence: mxcEvidence,
    },
    scopedReadiness: {
      standard: releaseProfiles.standard.releaseReady,
      plus: releaseProfiles.plus.releaseReady,
      pro: releaseProfiles.pro.releaseReady,
      plusStaticAndReputation: engineeringReady,
      plusSandboxEscalation: plusSandboxEscalationReady,
      proBehavioralSandbox: proBehavioralSandboxReady,
    },
    blockers: [...new Set(blockers)],
    status: productReleaseReady
      ? (runtimeCapabilitiesReadyOnCurrentHost
          ? 'PRODUCT_RELEASE_READY_ALL_RUNTIME_CAPABILITIES_AVAILABLE_ON_CURRENT_HOST'
          : 'PRODUCT_RELEASE_READY_RUNTIME_SANDBOX_SELF_CERTIFICATION_REQUIRED')
      : 'ENGINEERING_VALIDATION_PENDING',
  };
}

module.exports = {
  READINESS_SCHEMA_VERSION,
  ATTESTATION_PATH,
  loadMxcAttestation,
  validateMxcAttestation,
  verifyAttestedHarnessBlobs,
  evaluateIsolationReadiness,
};
