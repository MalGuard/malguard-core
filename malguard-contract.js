(function () {
'use strict';

/* ============================================================
   MalGuard Runtime Contract v1.0.0
   ------------------------------------------------------------
   Stable cross-module contract for the browser UI, scan worker,
   integration layer and tests. This is deliberately small: it
   standardizes envelopes, worker protocol and hard safety caps
   without forcing analyzers to share mutable state.
   ============================================================ */

const CONTRACT_VERSION = '1.1.0';
const RESULT_SCHEMA_VERSION = '1.0.0';
const WORKER_PROTOCOL = 2;

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const key of Object.keys(value)) deepFreeze(value[key]);
  return value;
}

const contract = {
  contractVersion: CONTRACT_VERSION,
  resultSchemaVersion: RESULT_SCHEMA_VERSION,
  workerProtocol: WORKER_PROTOCOL,

  modes: ['free', 'pro'],
  verdicts: ['safe', 'suspicious', 'malicious', 'inconclusive', 'invalid'],

  worker: {
    maxInputBytes: 150 * 1024 * 1024,
    maxFileNameLength: 1024,
    maxRequestIdLength: 128,
    initTimeoutMs: 8000,
    scanTimeoutMs: 45000,
    maxConcurrentScans: 1,
  },

  expectedModules: {
    engine: '2.2.1',
    multiLayer: '1.0.0',
    gtaModDetector: '1.0.0',
    archiveInspector: '1.1.0',
    archiveEntryReader: '1.1.1',
    scriptAnalyzer: '1.0.0',
    appIntegration: '1.5.0',
    workerHost: '1.1.0',
    workerClient: '1.2.0',
  },

  security: {
    uploadedContentExecutionAllowed: false,
    mainThreadFallbackAllowed: false,
    failClosedOnWorkerBootFailure: true,
    rawFileUploadToReputationServicesAllowed: false,
  },
};

deepFreeze(contract);

// Classic scripts and Dedicated Workers both expose window via the host setup.
window.MalGuardContract = contract;

})();
