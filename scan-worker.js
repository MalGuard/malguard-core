/* ============================================================
   MalGuard — scan-worker.js (Worker Host v1.1.0)
   ------------------------------------------------------------
   Dedicated Worker boundary for all heavy scanning. Uploaded
   content is never executed; the worker only runs bounded static
   analyzers. A hard client timeout can terminate this worker,
   which is the only reliable browser-level preemption for CPU work.
   ============================================================ */
'use strict';

self.window = self;

let bootError = null;
let pipelineReady = false;
let activeRequestId = null;

const WORKER_VERSION = '1.1.0';

function safeErrorPayload(error, fallbackCode) {
  const code = error && error.code ? String(error.code).slice(0, 120) : fallbackCode;
  const message = error && typeof error.message === 'string'
    ? error.message.slice(0, 500)
    : String(error || fallbackCode).slice(0, 500);
  return {
    code: code || 'WORKER_ERROR',
    name: error && error.name ? String(error.name).slice(0, 120) : 'Error',
    message,
  };
}

function fail(code, message) {
  const err = new Error(message || code);
  err.code = code;
  return err;
}

try {
  importScripts('malguard-contract.js');

  if (!self.MalGuardContract || self.MalGuardContract.workerProtocol !== 2) {
    throw fail('WORKER_CONTRACT_MISMATCH', 'MalGuard runtime contract is missing or incompatible.');
  }

  importScripts(
    'engine.js',
    'multilayer.js',
    'gta-mod-detector.js',
    'archive-inspector.js',
    'archive-entry-reader.js',
    'script-analyzer.js',
    'app.js'
  );

  const expected = self.MalGuardContract.expectedModules;
  if (!expected || expected.workerHost !== WORKER_VERSION) {
    throw fail('WORKER_HOST_VERSION_MISMATCH', `workerHost: expected ${expected && expected.workerHost ? expected.workerHost : 'missing'}, got ${WORKER_VERSION}`);
  }
  const actual = {
    engine: self.MalGuardEngine && self.MalGuardEngine.version,
    multiLayer: self.MultiLayerSecurity && self.MultiLayerSecurity.version,
    gtaModDetector: self.GtaModDetector && self.GtaModDetector.version,
    archiveInspector: self.ArchiveInspector && self.ArchiveInspector.version,
    archiveEntryReader: self.ArchiveEntryReader && self.ArchiveEntryReader.version,
    scriptAnalyzer: self.ScriptAnalyzer && self.ScriptAnalyzer.version,
    appIntegration: self.MalGuardApp && self.MalGuardApp.version,
  };

  for (const [name, version] of Object.entries(expected)) {
    if (name === 'workerHost' || name === 'workerClient' || name === 'selfTest') continue;
    if (actual[name] !== version) {
      throw fail('WORKER_MODULE_VERSION_MISMATCH', `${name}: expected ${version}, got ${actual[name] || 'missing'}`);
    }
  }

  if (typeof self.scanFileWithMode !== 'function') {
    throw fail('WORKER_PIPELINE_MISSING', 'scanFileWithMode was not registered by app.js.');
  }

  pipelineReady = true;
} catch (error) {
  bootError = safeErrorPayload(error, 'WORKER_BOOT_FAILED');
  pipelineReady = false;
}

const PROTOCOL = self.MalGuardContract ? self.MalGuardContract.workerProtocol : 2;

function postReady() {
  self.postMessage({
    type: 'worker_ready',
    ready: pipelineReady,
    protocol: PROTOCOL,
    workerVersion: WORKER_VERSION,
    contractVersion: self.MalGuardContract ? self.MalGuardContract.contractVersion : null,
    resultSchemaVersion: self.MalGuardContract ? self.MalGuardContract.resultSchemaVersion : null,
    capabilities: pipelineReady ? {
      isolation: 'dedicated_worker',
      maxConcurrentScans: 1,
      hardTerminationByClient: true,
      rawFileUpload: false,
    } : null,
    error: bootError,
  });
}

function validateScanRequest(message) {
  if (!pipelineReady) throw fail('WORKER_NOT_READY', 'Worker pipeline is not ready.');

  const limits = self.MalGuardContract.worker;
  const requestId = typeof message.requestId === 'string' ? message.requestId : '';
  if (!requestId || requestId.length > limits.maxRequestIdLength) {
    throw fail('INVALID_REQUEST_ID', 'Missing or oversized requestId.');
  }

  if (message.mode !== 'free' && message.mode !== 'pro') {
    throw fail('INVALID_MODE', 'Mode must be free or pro.');
  }

  const file = message.file;
  if (!file || typeof file.name !== 'string' || typeof file.arrayBuffer !== 'function') {
    throw fail('INVALID_FILE', 'A valid File/Blob-like object is required.');
  }
  if (!file.name || file.name.length > limits.maxFileNameLength) {
    throw fail('INVALID_FILE_NAME', 'File name is empty or exceeds the safety limit.');
  }
  if (!Number.isFinite(file.size) || file.size < 0 || file.size > limits.maxInputBytes) {
    throw fail('WORKER_INPUT_TOO_LARGE', 'Input size exceeds the worker boundary limit.');
  }

  return { requestId, file, mode: message.mode };
}

self.addEventListener('message', async (event) => {
  const message = event && event.data ? event.data : {};

  if (message.type === 'ping') {
    postReady();
    return;
  }

  if (message.type !== 'scan') return;

  let request;
  try {
    request = validateScanRequest(message);
  } catch (error) {
    self.postMessage({
      type: 'scan_error',
      requestId: typeof message.requestId === 'string' ? message.requestId.slice(0, 128) : '',
      error: safeErrorPayload(error, 'INVALID_REQUEST'),
    });
    return;
  }

  if (activeRequestId !== null) {
    self.postMessage({
      type: 'scan_error',
      requestId: request.requestId,
      error: safeErrorPayload(fail('WORKER_BUSY', 'Only one scan may run in this worker at a time.'), 'WORKER_BUSY'),
    });
    return;
  }

  activeRequestId = request.requestId;
  const startedAt = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();

  try {
    const result = await self.scanFileWithMode(request.file, request.mode);
    const finishedAt = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();

    if (!result || typeof result !== 'object') {
      throw fail('WORKER_INVALID_RESULT', 'Scan pipeline returned a non-object result.');
    }
    const cfg = self.MalGuardContract;
    if (result.resultSchemaVersion !== cfg.resultSchemaVersion) {
      throw fail('RESULT_SCHEMA_MISMATCH', 'Scan pipeline returned an incompatible result schema.');
    }
    if (!cfg.verdicts.includes(result.finalVerdict)) {
      throw fail('WORKER_INVALID_VERDICT', 'Scan pipeline returned a verdict outside the runtime contract.');
    }
    if (result.mode !== request.mode) {
      throw fail('WORKER_MODE_MISMATCH', `Scan pipeline returned mode ${result.mode || 'missing'} for ${request.mode} request.`);
    }
    if (result.appIntegrationVersion !== cfg.expectedModules.appIntegration) {
      throw fail('WORKER_APP_VERSION_MISMATCH', 'Scan pipeline returned an incompatible app integration version.');
    }

    result.execution = {
      context: 'web_worker',
      workerVersion: WORKER_VERSION,
      protocol: PROTOCOL,
      durationMs: Math.max(0, Math.round(finishedAt - startedAt)),
      hardTimeoutEnforcedByClient: true,
    };

    self.postMessage({ type: 'scan_result', requestId: request.requestId, result });
  } catch (error) {
    self.postMessage({
      type: 'scan_error',
      requestId: request.requestId,
      error: safeErrorPayload(error, 'SCAN_FAILED'),
    });
  } finally {
    activeRequestId = null;
  }
});

postReady();
