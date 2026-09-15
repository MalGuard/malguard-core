/* ============================================================
   MalGuard — scan-worker-client.js (Worker Client v1.1.0)
   ------------------------------------------------------------
   Strict browser bridge to scan-worker.js.

   Hardening policy:
   - no silent main-thread fallback in production
   - one active scan at a time
   - abort/timeout terminates the worker for true preemption
   - worker boot/version/protocol failures fail closed
   ============================================================ */
(function () {
'use strict';

const CLIENT_VERSION = '1.2.0';
const WORKER_URL = (typeof document !== 'undefined' && document.currentScript && document.currentScript.src)
  ? new URL('scan-worker.js', document.currentScript.src).href
  : 'scan-worker.js';

let worker = null;
let readyPromise = null;
let requestCounter = 0;
let active = null;
let scanReserved = false;

function contract() {
  if (!window.MalGuardContract) {
    const err = new Error('MalGuard runtime contract is missing.');
    err.code = 'WORKER_CONTRACT_MISSING';
    throw err;
  }
  const cfg = window.MalGuardContract;
  if (!cfg.expectedModules || cfg.expectedModules.workerClient !== CLIENT_VERSION) {
    const err = new Error(`Worker client version mismatch: expected ${cfg.expectedModules && cfg.expectedModules.workerClient ? cfg.expectedModules.workerClient : 'missing'}, got ${CLIENT_VERSION}.`);
    err.code = 'WORKER_CLIENT_VERSION_MISMATCH';
    throw err;
  }
  return cfg;
}

function makeError(code, message) {
  const err = new Error(message || code);
  err.code = code;
  return err;
}

function canUseWorker() {
  return typeof window.Worker === 'function';
}

function cleanupActive() {
  if (!active) return;
  clearTimeout(active.timer);
  if (active.signal && active.abortHandler) {
    try { active.signal.removeEventListener('abort', active.abortHandler); } catch (_) { /* noop */ }
  }
  active = null;
}

function terminateWorker(reasonCode, reasonMessage) {
  const current = worker;
  worker = null;
  readyPromise = null;
  if (current) {
    try { current.terminate(); } catch (_) { /* noop */ }
  }

  if (active) {
    const reject = active.reject;
    cleanupActive();
    reject(makeError(reasonCode || 'WORKER_TERMINATED', reasonMessage || 'Scan worker was terminated.'));
  }
}

function ensureWorker() {
  const cfg = contract();
  if (worker && readyPromise) return readyPromise;
  if (!canUseWorker()) {
    return Promise.reject(makeError('WORKER_UNSUPPORTED', 'This browser does not support Dedicated Web Workers.'));
  }

  readyPromise = new Promise((resolve, reject) => {
    let settled = false;
    let initTimer = null;

    const failInit = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(initTimer);
      const current = worker;
      worker = null;
      readyPromise = null;
      if (current) {
        try { current.terminate(); } catch (_) { /* noop */ }
      }
      reject(error);
    };

    try {
      worker = new Worker(WORKER_URL);
    } catch (error) {
      failInit(makeError('WORKER_CREATE_FAILED', error && error.message ? error.message : 'Could not create scan worker.'));
      return;
    }

    worker.addEventListener('message', (event) => {
      const data = event && event.data ? event.data : {};

      if (data.type === 'worker_ready') {
        if (settled) return;
        if (data.ready !== true) {
          const payload = data.error || {};
          failInit(makeError(payload.code || 'WORKER_BOOT_FAILED', payload.message || 'Worker failed to initialize.'));
          return;
        }
        if (data.protocol !== cfg.workerProtocol) {
          failInit(makeError('WORKER_PROTOCOL_MISMATCH', `Expected protocol ${cfg.workerProtocol}, got ${data.protocol}.`));
          return;
        }
        if (data.contractVersion !== cfg.contractVersion) {
          failInit(makeError('WORKER_CONTRACT_MISMATCH', 'Worker and page runtime contracts do not match.'));
          return;
        }
        if (data.workerVersion !== cfg.expectedModules.workerHost) {
          failInit(makeError('WORKER_VERSION_MISMATCH', `Expected worker ${cfg.expectedModules.workerHost}, got ${data.workerVersion || 'missing'}.`));
          return;
        }
        if (data.resultSchemaVersion !== cfg.resultSchemaVersion) {
          failInit(makeError('RESULT_SCHEMA_MISMATCH', 'Worker ready schema does not match this build.'));
          return;
        }
        settled = true;
        clearTimeout(initTimer);
        resolve(data);
        return;
      }

      if (data.type !== 'scan_result' && data.type !== 'scan_error') return;
      if (!active || String(data.requestId || '') !== active.requestId) return;

      const current = active;
      cleanupActive();

      if (data.type === 'scan_result') {
        const result = data.result;
        if (!result || typeof result !== 'object') {
          current.reject(makeError('WORKER_INVALID_RESULT', 'Worker returned an invalid result.'));
          return;
        }
        if (result.resultSchemaVersion !== cfg.resultSchemaVersion) {
          current.reject(makeError('RESULT_SCHEMA_MISMATCH', 'Worker result schema does not match this build.'));
          return;
        }
        if (!cfg.verdicts.includes(result.finalVerdict)) {
          current.reject(makeError('WORKER_INVALID_VERDICT', 'Worker returned a verdict outside the runtime contract.'));
          return;
        }
        if (result.mode !== current.mode) {
          current.reject(makeError('WORKER_MODE_MISMATCH', `Worker returned mode ${result.mode || 'missing'} for ${current.mode} request.`));
          return;
        }
        if (result.appIntegrationVersion !== cfg.expectedModules.appIntegration) {
          current.reject(makeError('WORKER_APP_VERSION_MISMATCH', 'Worker result came from an incompatible app integration version.'));
          return;
        }
        current.resolve(result);
      } else {
        const payload = data.error || {};
        current.reject(makeError(payload.code || 'WORKER_SCAN_FAILED', payload.message || 'Worker scan failed.'));
      }
    });

    worker.addEventListener('error', (event) => {
      const message = event && event.message ? event.message : 'Unexpected worker runtime error.';
      if (!settled) {
        failInit(makeError('WORKER_RUNTIME_ERROR', message));
      } else {
        terminateWorker('WORKER_RUNTIME_ERROR', message);
      }
    });

    worker.addEventListener('messageerror', () => {
      if (!settled) {
        failInit(makeError('WORKER_MESSAGE_ERROR', 'Worker message deserialization failed during initialization.'));
      } else {
        terminateWorker('WORKER_MESSAGE_ERROR', 'Worker message deserialization failed.');
      }
    });

    initTimer = setTimeout(() => {
      failInit(makeError('WORKER_INIT_TIMEOUT', 'Timed out while initializing scan worker.'));
    }, cfg.worker.initTimeoutMs);

    try { worker.postMessage({ type: 'ping' }); } catch (_) { /* timeout will fail closed */ }
  });

  return readyPromise;
}

function validateClientInput(file, mode) {
  const cfg = contract();
  if (!file || typeof file.name !== 'string') throw makeError('INVALID_FILE', 'A valid File is required.');
  if (!file.name || file.name.length > cfg.worker.maxFileNameLength) throw makeError('INVALID_FILE_NAME', 'Invalid file name.');
  if (!Number.isFinite(file.size) || file.size < 0 || file.size > cfg.worker.maxInputBytes) {
    throw makeError('WORKER_INPUT_TOO_LARGE', 'File exceeds the worker boundary limit.');
  }
  if (mode !== 'free' && mode !== 'pro') throw makeError('INVALID_MODE', 'Mode must be free or pro.');
}

async function warmupScanWorker() {
  return ensureWorker();
}

async function scanFileInWorker(file, mode, options) {
  const cfg = contract();
  validateClientInput(file, mode);
  const normalizedMode = mode;

  if (active || scanReserved) throw makeError('WORKER_BUSY', 'Another scan is already running or starting.');
  scanReserved = true;

  const opts = options && typeof options === 'object' ? options : {};
  const signal = opts.signal || null;
  if (signal && signal.aborted) { scanReserved = false; throw makeError('WORKER_ABORTED', 'Scan was cancelled before it started.'); }

  try {
    await ensureWorker();
  } catch (error) {
    scanReserved = false;
    throw error;
  }
  if (signal && signal.aborted) {
    scanReserved = false;
    throw makeError('WORKER_ABORTED', 'Scan was cancelled before it started.');
  }

  const requestId = `scan-${Date.now().toString(36)}-${(++requestCounter).toString(36)}`;

  return new Promise((resolve, reject) => {
    scanReserved = false;
    const timeoutMs = Number.isFinite(opts.timeoutMs)
      ? Math.max(1000, Math.min(opts.timeoutMs, cfg.worker.scanTimeoutMs))
      : cfg.worker.scanTimeoutMs;

    const timer = setTimeout(() => {
      terminateWorker('WORKER_SCAN_TIMEOUT', 'Scan exceeded the hard worker time limit. No SAFE result was produced.');
    }, timeoutMs);

    const abortHandler = () => {
      terminateWorker('WORKER_ABORTED', 'Scan was cancelled. No verdict was produced.');
    };

    active = { requestId, mode: normalizedMode, resolve, reject, timer, signal, abortHandler };
    if (signal) signal.addEventListener('abort', abortHandler, { once: true });

    try {
      worker.postMessage({ type: 'scan', requestId, file, mode: normalizedMode });
    } catch (error) {
      cleanupActive();
      reject(makeError('WORKER_POST_FAILED', error && error.message ? error.message : 'Could not send file to scan worker.'));
    }
  });
}

function cancelActiveScan() {
  if (!active) return false;
  terminateWorker('WORKER_ABORTED', 'Scan was cancelled. No verdict was produced.');
  return true;
}

function shutdownScanWorker() {
  terminateWorker('WORKER_SHUTDOWN', 'Worker shutdown requested.');
}

window.MalGuardWorkerScanner = Object.freeze({
  version: CLIENT_VERSION,
  protocol: contract().workerProtocol,
  scan: scanFileInWorker,
  warmup: warmupScanWorker,
  cancel: cancelActiveScan,
  shutdown: shutdownScanWorker,
  isSupported: canUseWorker,
  hasActiveScan: () => Boolean(active || scanReserved),
});
window.scanFileInWorker = scanFileInWorker;

})();
