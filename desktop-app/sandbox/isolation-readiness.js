'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const READINESS_SCHEMA_VERSION = '1.1.0';
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
  const windowsSandboxCertified = !!(
    controllerSelfTest &&
    controllerSelfTest.releaseReady === true &&
    controllerSelfTest.windowsSandbox &&
    controllerSelfTest.windowsSandbox.releaseGrade === true
  );
  const engineeringReady = embeddedChecksPassed === true && mxcEvidence.ok === true;
  const proBehavioralSandboxReady = windowsSandboxCertified;
  const releaseReady = engineeringReady && proBehavioralSandboxReady;

  // A deployable profile is intentionally narrower than a full-product release.
  // When the Hyper-V-backed Windows Sandbox runtime is not certified, MalGuard can
  // still ship a fully validated Standard profile while Plus/Pro features that can
  // escalate to behavioral execution remain locked. This avoids blocking the whole
  // product on a host capability without weakening the sandbox boundary.
  const releaseProfiles = {
    standard: {
      ready: engineeringReady,
      coverage: engineeringReady ? 100 : 0,
      behavioralExecution: false,
    },
    plus: {
      ready: engineeringReady && windowsSandboxCertified,
      coverage: engineeringReady && windowsSandboxCertified ? 100 : (engineeringReady ? 75 : 0),
      behavioralExecution: true,
      requiresWindowsSandboxCertification: true,
    },
    pro: {
      ready: engineeringReady && windowsSandboxCertified,
      coverage: engineeringReady && windowsSandboxCertified ? 100 : (engineeringReady ? 50 : 0),
      behavioralExecution: true,
      requiresWindowsSandboxCertification: true,
    },
  };
  const deployableReleaseReady = releaseProfiles.standard.ready === true;
  const deployableReleaseProfile = releaseReady ? 'standard-plus-pro' : (deployableReleaseReady ? 'standard-only' : 'none');
  const lockedCapabilities = [];
  if (!releaseProfiles.plus.ready) lockedCapabilities.push('plus-sandbox-escalation');
  if (!releaseProfiles.pro.ready) lockedCapabilities.push('pro-behavioral-sandbox');

  const blockers = [];
  if (embeddedChecksPassed !== true) blockers.push('embedded_validation_incomplete');
  if (mxcEvidence.ok !== true) blockers.push(mxcEvidence.code || 'mxc_processcontainer_ci_validation_missing');
  if (!windowsSandboxCertified) blockers.push('windows_sandbox_runtime_certification_pending');

  const deployableBlockers = [];
  if (!engineeringReady) deployableBlockers.push('engineering_validation_incomplete');

  return {
    schemaVersion: READINESS_SCHEMA_VERSION,
    engineeringReady,
    deployableReleaseReady,
    deployableReleaseProfile,
    deployableBlockers,
    releaseProfiles,
    fullProductReleaseReady: releaseReady,
    releaseReady,
    windowsSandboxCertified,
    proBehavioralSandboxReady,
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
      standard: releaseProfiles.standard.ready,
      plusStaticAndReputation: engineeringReady,
      plusSandboxEscalation: proBehavioralSandboxReady,
      proBehavioralSandbox: proBehavioralSandboxReady,
    },
    blockers: [...new Set(blockers)],
    status: releaseReady
      ? 'FULL_RELEASE_READY'
      : (deployableReleaseReady ? 'STANDARD_RELEASE_READY_PLUS_PRO_LOCKED' : 'ENGINEERING_VALIDATION_PENDING'),
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
