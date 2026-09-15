'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { webcrypto } = require('crypto');

const ROOT = path.resolve(__dirname, '..');
const FIXTURES = path.join(__dirname, 'fixtures');

class FileLike {
  constructor(name, input, declaredSize) {
    this.name = name;
    this._bytes = Buffer.isBuffer(input) ? Buffer.from(input) : Buffer.from(input || '', 'utf8');
    this.size = declaredSize == null ? this._bytes.length : declaredSize;
  }
  async arrayBuffer() {
    return this._bytes.buffer.slice(this._bytes.byteOffset, this._bytes.byteOffset + this._bytes.byteLength);
  }
  slice(start, end) {
    return new FileLike(this.name, this._bytes.subarray(start || 0, end == null ? this._bytes.length : end));
  }
}

function loadFile(context, filename) {
  vm.runInContext(fs.readFileSync(path.join(ROOT, filename), 'utf8'), context, { filename });
}

function waitFor(predicate, timeoutMs = 4000) {
  const start = Date.now();
  return new Promise((resolve, reject) => {
    const timer = setInterval(() => {
      const value = predicate();
      if (value) {
        clearInterval(timer);
        resolve(value);
      } else if (Date.now() - start > timeoutMs) {
        clearInterval(timer);
        reject(new Error('Timed out waiting for worker test result'));
      }
    }, 5);
  });
}

function hostContext() {
  const messages = [];
  const listeners = {};
  const context = {
    console,
    TextDecoder,
    TextEncoder,
    crypto: webcrypto,
    performance,
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
    ReadableStream,
    DecompressionStream,
    Blob,
    Response,
    AbortController,
    fetch: async (url) => {
      if (String(url) === 'rules.json') {
        return new Response(fs.readFileSync(path.join(ROOT, 'rules.json')), {
          status: 200, headers: { 'content-type': 'application/json' },
        });
      }
      return new Response('{}', { status: 404, headers: { 'content-type': 'application/json' } });
    },
  };
  context.self = context;
  context.postMessage = (message) => messages.push(message);
  context.addEventListener = (type, callback) => { listeners[type] = callback; };
  vm.createContext(context);
  context.importScripts = (...files) => files.forEach(file => loadFile(context, file));
  return { context, messages, listeners };
}

async function workerHostTests() {
  const { context, messages, listeners } = hostContext();
  loadFile(context, 'scan-worker.js');

  const ready = messages.find(m => m.type === 'worker_ready');
  assert.ok(ready, 'worker_ready was not posted');
  assert.equal(ready.ready, true, ready.error && ready.error.message);
  assert.equal(ready.protocol, 2);
  assert.equal(ready.workerVersion, '1.1.0');
  assert.equal(ready.contractVersion, '1.1.0');
  assert.equal(ready.resultSchemaVersion, '1.0.0');
  assert.equal(ready.capabilities.maxConcurrentScans, 1);

  const lua = new FileLike('worker-benign.lua', 'print("GTA V worker test")');
  listeners.message({ data: { type: 'scan', requestId: 'lua-1', file: lua, mode: 'pro' } });
  const luaMsg = await waitFor(() => messages.find(m => m.type === 'scan_result' && m.requestId === 'lua-1'));
  assert.equal(luaMsg.result.finalVerdict, 'safe');
  assert.equal(luaMsg.result.resultSchemaVersion, '1.0.0');
  assert.equal(luaMsg.result.execution.context, 'web_worker');

  const zip = new FileLike('gtav-benign-scripts.zip', fs.readFileSync(path.join(FIXTURES, 'gtav-benign-scripts.zip')));
  listeners.message({ data: { type: 'scan', requestId: 'zip-1', file: zip, mode: 'pro' } });
  const zipMsg = await waitFor(() => messages.find(m => m.type === 'scan_result' && m.requestId === 'zip-1'));
  assert.equal(zipMsg.result.finalVerdict, 'safe');
  assert.equal(zipMsg.result.archiveScriptResults.length, 2);

  listeners.message({ data: { type: 'scan', requestId: 'bad-mode', file: lua, mode: 'root' } });
  const badMode = await waitFor(() => messages.find(m => m.type === 'scan_error' && m.requestId === 'bad-mode'));
  assert.equal(badMode.error.code, 'INVALID_MODE');

  const huge = new FileLike('huge.zip', Buffer.from('x'), 151 * 1024 * 1024);
  listeners.message({ data: { type: 'scan', requestId: 'huge-1', file: huge, mode: 'pro' } });
  const hugeMsg = await waitFor(() => messages.find(m => m.type === 'scan_error' && m.requestId === 'huge-1'));
  assert.equal(hugeMsg.error.code, 'WORKER_INPUT_TOO_LARGE');

  // Concurrency gate: keep one request pending, then submit a second.
  let release;
  context.scanFileWithMode = () => new Promise(resolve => { release = () => resolve({ resultSchemaVersion: '1.0.0', appIntegrationVersion: '1.5.1', mode: 'pro', finalVerdict: 'safe' }); });
  listeners.message({ data: { type: 'scan', requestId: 'slow-1', file: lua, mode: 'pro' } });
  await new Promise(resolve => setTimeout(resolve, 5));
  listeners.message({ data: { type: 'scan', requestId: 'slow-2', file: lua, mode: 'pro' } });
  const busyMsg = await waitFor(() => messages.find(m => m.type === 'scan_error' && m.requestId === 'slow-2'));
  assert.equal(busyMsg.error.code, 'WORKER_BUSY');
  release();
  await waitFor(() => messages.find(m => m.type === 'scan_result' && m.requestId === 'slow-1'));

  // Host must reject a pipeline result that violates the cross-module result contract.
  context.scanFileWithMode = async () => ({
    resultSchemaVersion: '1.0.0', appIntegrationVersion: '1.5.1', mode: 'free', finalVerdict: 'safe',
  });
  listeners.message({ data: { type: 'scan', requestId: 'bad-result-mode', file: lua, mode: 'pro' } });
  const badResultMode = await waitFor(() => messages.find(m => m.type === 'scan_error' && m.requestId === 'bad-result-mode'));
  assert.equal(badResultMode.error.code, 'WORKER_MODE_MISMATCH');

  context.scanFileWithMode = async () => ({
    resultSchemaVersion: '9.9.9', appIntegrationVersion: '1.5.1', mode: 'pro', finalVerdict: 'safe',
  });
  listeners.message({ data: { type: 'scan', requestId: 'bad-result-schema', file: lua, mode: 'pro' } });
  const badResultSchema = await waitFor(() => messages.find(m => m.type === 'scan_error' && m.requestId === 'bad-result-schema'));
  assert.equal(badResultSchema.error.code, 'RESULT_SCHEMA_MISMATCH');

  console.log('✓ Worker host hardening: boot/version/schema/input/concurrency checks passed');
}

function makeClientContext(WorkerClass) {
  const context = {
    console,
    performance,
    setTimeout,
    clearTimeout,
    queueMicrotask,
    AbortController,
    Worker: WorkerClass,
    window: null,
  };
  context.window = context;
  vm.createContext(context);
  loadFile(context, 'malguard-contract.js');
  loadFile(context, 'scan-worker-client.js');
  return context;
}

async function workerClientTests() {
  class SuccessWorker {
    constructor() {
      this.listeners = { message: [], error: [], messageerror: [] };
      this.terminated = false;
    }
    addEventListener(type, fn) { this.listeners[type].push(fn); }
    emit(type, data) { for (const fn of this.listeners[type] || []) fn({ data }); }
    postMessage(message) {
      if (message.type === 'ping') {
        queueMicrotask(() => this.emit('message', {
          type: 'worker_ready', ready: true, protocol: 2, workerVersion: '1.1.0',
          contractVersion: '1.1.0', resultSchemaVersion: '1.0.0',
        }));
      } else if (message.type === 'scan') {
        queueMicrotask(() => this.emit('message', {
          type: 'scan_result', requestId: message.requestId,
          result: { resultSchemaVersion: '1.0.0', appIntegrationVersion: '1.5.1', mode: 'pro', finalVerdict: 'safe', execution: { context: 'web_worker' } },
        }));
      }
    }
    terminate() { this.terminated = true; }
  }

  let c = makeClientContext(SuccessWorker);
  let result = await c.scanFileInWorker({ name: 'x.lua', size: 12 }, 'pro');
  assert.equal(result.finalVerdict, 'safe');
  assert.equal(c.MalGuardWorkerScanner.version, '1.2.0');
  assert.equal(c.MalGuardWorkerScanner.protocol, 2);

  // Adversarial client race: two scans started during worker initialization must not both pass the gate.
  class SlowInitWorker extends SuccessWorker {
    postMessage(message) {
      if (message.type === 'ping') {
        setTimeout(() => this.emit('message', {
          type: 'worker_ready', ready: true, protocol: 2, workerVersion: '1.1.0',
          contractVersion: '1.1.0', resultSchemaVersion: '1.0.0',
        }), 20);
      } else {
        super.postMessage(message);
      }
    }
  }
  c = makeClientContext(SlowInitWorker);
  const firstRace = c.scanFileInWorker({ name: 'a.lua', size: 12 }, 'pro');
  await assert.rejects(
    () => c.scanFileInWorker({ name: 'b.lua', size: 12 }, 'pro'),
    err => err && err.code === 'WORKER_BUSY'
  );
  await firstRace;

  // Unsupported Worker must fail closed. No main-thread fallback exists.
  c = makeClientContext(undefined);
  await assert.rejects(
    () => c.scanFileInWorker({ name: 'x.lua', size: 12 }, 'pro'),
    err => err && err.code === 'WORKER_UNSUPPORTED'
  );

  class BadProtocolWorker extends SuccessWorker {
    postMessage(message) {
      if (message.type === 'ping') {
        queueMicrotask(() => this.emit('message', {
          type: 'worker_ready', ready: true, protocol: 99, workerVersion: 'x',
          contractVersion: '1.1.0', resultSchemaVersion: '1.0.0',
        }));
      }
    }
  }
  c = makeClientContext(BadProtocolWorker);
  await assert.rejects(
    () => c.scanFileInWorker({ name: 'x.lua', size: 12 }, 'pro'),
    err => err && err.code === 'WORKER_PROTOCOL_MISMATCH'
  );

  class BadVersionWorker extends SuccessWorker {
    postMessage(message) {
      if (message.type === 'ping') {
        queueMicrotask(() => this.emit('message', {
          type: 'worker_ready', ready: true, protocol: 2, workerVersion: '0.0.0',
          contractVersion: '1.1.0', resultSchemaVersion: '1.0.0',
        }));
      }
    }
  }
  c = makeClientContext(BadVersionWorker);
  await assert.rejects(
    () => c.scanFileInWorker({ name: 'x.lua', size: 12 }, 'pro'),
    err => err && err.code === 'WORKER_VERSION_MISMATCH'
  );

  class BadReadySchemaWorker extends SuccessWorker {
    postMessage(message) {
      if (message.type === 'ping') {
        queueMicrotask(() => this.emit('message', {
          type: 'worker_ready', ready: true, protocol: 2, workerVersion: '1.1.0',
          contractVersion: '1.1.0', resultSchemaVersion: '9.9.9',
        }));
      }
    }
  }
  c = makeClientContext(BadReadySchemaWorker);
  await assert.rejects(
    () => c.scanFileInWorker({ name: 'x.lua', size: 12 }, 'pro'),
    err => err && err.code === 'RESULT_SCHEMA_MISMATCH'
  );

  class WrongResultModeWorker extends SuccessWorker {
    postMessage(message) {
      if (message.type === 'ping') return super.postMessage(message);
      if (message.type === 'scan') {
        queueMicrotask(() => this.emit('message', {
          type: 'scan_result', requestId: message.requestId,
          result: { resultSchemaVersion: '1.0.0', appIntegrationVersion: '1.5.1', mode: 'free', finalVerdict: 'safe' },
        }));
      }
    }
  }
  c = makeClientContext(WrongResultModeWorker);
  await assert.rejects(
    () => c.scanFileInWorker({ name: 'x.lua', size: 12 }, 'pro'),
    err => err && err.code === 'WORKER_MODE_MISMATCH'
  );

  class HangingWorker extends SuccessWorker {
    postMessage(message) {
      if (message.type === 'ping') super.postMessage(message);
      // scan deliberately never answers
    }
  }
  c = makeClientContext(HangingWorker);
  const controller = new c.AbortController();
  const pending = c.scanFileInWorker({ name: 'x.lua', size: 12 }, 'pro', { signal: controller.signal });
  await new Promise(resolve => setTimeout(resolve, 5));
  controller.abort();
  await assert.rejects(() => pending, err => err && err.code === 'WORKER_ABORTED');
  assert.equal(c.MalGuardWorkerScanner.hasActiveScan(), false);

  // Runtime crash after initialization must terminate and reject, never synthesize a verdict.
  class CrashWorker extends SuccessWorker {
    postMessage(message) {
      if (message.type === 'ping') return super.postMessage(message);
      if (message.type === 'scan') queueMicrotask(() => { for (const fn of this.listeners.error) fn({ message: 'synthetic worker crash' }); });
    }
  }
  c = makeClientContext(CrashWorker);
  await assert.rejects(
    () => c.scanFileInWorker({ name: 'x.lua', size: 12 }, 'pro'),
    err => err && err.code === 'WORKER_RUNTIME_ERROR'
  );
  assert.equal(c.MalGuardWorkerScanner.hasActiveScan(), false);

  // Hard timeout must really terminate a hung worker and reject fail-closed.
  c = makeClientContext(HangingWorker);
  await assert.rejects(
    () => c.scanFileInWorker({ name: 'x.lua', size: 12 }, 'pro', { timeoutMs: 1000 }),
    err => err && err.code === 'WORKER_SCAN_TIMEOUT'
  );
  assert.equal(c.MalGuardWorkerScanner.hasActiveScan(), false);

  console.log('✓ Worker client hardening: isolation/protocol/race/crash/timeout/abort behavior passed');
}

(async () => {
  await workerHostTests();
  await workerClientTests();
  console.log('✓ All Web Worker hardening tests passed');
})().catch(err => {
  console.error(err && err.stack ? err.stack : err);
  process.exit(1);
});
