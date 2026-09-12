(function () {
'use strict';
const SELF_TEST_VERSION = '1.1.0';
function fileLike(name, input) {
  const data = input instanceof Uint8Array ? input : new TextEncoder().encode(String(input));
  return {
    name, size: data.byteLength,
    slice(start, end) { return fileLike(name, data.slice(start || 0, end == null ? data.length : end)); },
    async arrayBuffer() { return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength); },
  };
}
async function run() {
  const startedAt = Date.now();
  const checks = [];
  async function check(id, fn) {
    try {
      const detail = await fn();
      checks.push({ id, ok: true, detail: String(detail || 'ok') });
    } catch (error) {
      checks.push({ id, ok: false, detail: String((error && (error.code || error.message)) || error || 'failed') });
    }
  }

  await check('runtime-contract', async () => {
    const c = window.MalGuardContract;
    if (!c || !c.contractVersion || !c.resultSchemaVersion || c.workerProtocol !== 2) throw new Error('runtime_contract_mismatch');
    return `contract=${c.contractVersion} schema=${c.resultSchemaVersion}`;
  });

  await check('module-versions', async () => {
    const c = window.MalGuardContract;
    if (!c || !c.expectedModules) throw new Error('expected_modules_missing');
    const actual = {
      engine: window.MalGuardEngine && window.MalGuardEngine.version,
      multiLayer: window.MultiLayerSecurity && window.MultiLayerSecurity.version,
      gtaModDetector: window.GtaModDetector && window.GtaModDetector.version,
      archiveInspector: window.ArchiveInspector && window.ArchiveInspector.version,
      archiveEntryReader: window.ArchiveEntryReader && window.ArchiveEntryReader.version,
      scriptAnalyzer: window.ScriptAnalyzer && window.ScriptAnalyzer.version,
      appIntegration: window.MalGuardApp && window.MalGuardApp.version,
      workerClient: window.MalGuardWorkerScanner && window.MalGuardWorkerScanner.version,
    };
    for (const [name, version] of Object.entries(actual)) {
      if (!version || c.expectedModules[name] !== version) throw new Error(`${name}: expected ${c.expectedModules[name] || 'missing'}, got ${version || 'missing'}`);
    }
    return 'all core module versions match contract';
  });

  await check('script-benign-control', async () => {
    const r = await window.ScriptAnalyzer.analyze(fileLike('selftest.lua', 'local x = 2 + 2\nprint(x)'));
    if (!r || r.errorCode || r.verdict !== 'safe') throw new Error(`unexpected=${r && r.verdict}/${r && r.errorCode}`);
    return r.verdict;
  });

  await check('script-binary-fail-closed', async () => {
    const r = await window.ScriptAnalyzer.analyze(fileLike('selftest.lua', new Uint8Array([0,1,2,0,255,3,4])));
    if (!r || r.verdict === 'safe' || !r.errorCode) throw new Error('binary_input_not_rejected');
    return `${r.verdict}/${r.errorCode}`;
  });

  await check('engine-invalid-input-fail-closed', async () => {
    // Empty input exercises the Engine boundary without triggering any reputation/network lookup.
    const r = await window.scanFile(fileLike('selftest.asi', new Uint8Array(0)));
    if (!r || r.verdict === 'safe' || r.peValid === true) throw new Error('invalid_engine_input_escaped');
    return `${r.verdict}/${r.errorCode || 'no-code'}`;
  });

  await check('archive-malformed-fail-closed', async () => {
    const r = await window.ArchiveInspector.inspect(fileLike('selftest.zip', new Uint8Array([0x50,0x4b,0x03,0x04,0,0,0,0])));
    if (!r || r.inspectionStatus === 'completed' || r.inspectionSucceeded === true) throw new Error('malformed_zip_escaped');
    return r.inspectionStatus;
  });

  await check('invalid-mode-fail-closed', async () => {
    try {
      await window.scanFileWithMode(fileLike('selftest.lua', 'print(1)'), 'pr0');
    } catch (error) {
      if (error && error.code === 'INVALID_MODE') return 'INVALID_MODE';
      throw error;
    }
    throw new Error('invalid_mode_was_accepted');
  });

  await check('worker-isolation', async () => {
    const c = window.MalGuardContract;
    if (!window.MalGuardWorkerScanner || !window.MalGuardWorkerScanner.isSupported()) throw new Error('dedicated_worker_unsupported');
    const ready = await window.MalGuardWorkerScanner.warmup();
    if (!ready || ready.ready !== true || ready.protocol !== c.workerProtocol || ready.resultSchemaVersion !== c.resultSchemaVersion) throw new Error('worker_ready_contract_mismatch');
    return `protocol=${ready.protocol}`;
  });

  const ok = checks.length > 0 && checks.every(x => x.ok);
  return Object.freeze({ selfTestVersion: SELF_TEST_VERSION, ok, passed: ok, checks, durationMs: Date.now() - startedAt, timestamp: new Date().toISOString() });
}
window.MalGuardSelfTest = Object.freeze({ version: SELF_TEST_VERSION, run });
})();
