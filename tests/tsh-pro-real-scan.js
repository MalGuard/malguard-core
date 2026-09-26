'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { ScannerBridge } = require('../desktop-app/scanner-bridge.js');
const { ModelScanPipelineManager } = require('../desktop-app/pro-scan-pipeline.js');

function waitFor(manager, id, timeoutMs = 240000) {
  const started = Date.now();
  return new Promise((resolve, reject) => {
    const tick = () => {
      const s = manager.snapshot(id);
      if (!s) return reject(new Error('session disappeared'));
      if (s.state === 'completed' || s.state === 'failed') return resolve(s);
      if (Date.now() - started > timeoutMs) return reject(new Error('TSH Pro pipeline timeout'));
      setTimeout(tick, 100);
    };
    tick();
  });
}

function noSandbox() {
  return {
    preflightSample: async filePath => {
      const ext = path.extname(filePath).toLowerCase();
      if (ext === '.asi' || ext === '.dll') {
        return { ok:false, code:'SANDBOX_SAMPLE_TYPE_UNSUPPORTED', extension:ext };
      }
      const st = await fs.promises.stat(filePath);
      return { ok:true, sha256:'0'.repeat(64), size:st.size, extension:ext, revalidated:true };
    },
    analyzeUntrustedSample: async () => ({
      ok:false,
      verdict:'inconclusive',
      code:'SANDBOX_UNAVAILABLE',
      sandboxLaunched:false,
      sampleExecutionStarted:false,
    }),
  };
}

function engineMap(localResult) {
  const list = localResult && localResult.multiEngine && Array.isArray(localResult.multiEngine.engines)
    ? localResult.multiEngine.engines : [];
  return Object.fromEntries(list.map(e => [e.name, e]));
}

async function runNoSandboxCase(scanner, filePath, label) {
  const manager = new ModelScanPipelineManager({ scanner, sandbox:noSandbox() });
  const started = manager.start(filePath, 'pro', { allowCloudFallback:false, allowAiEvidence:false });
  const session = await waitFor(manager, started.id);

  assert.equal(session.state, 'completed', label + ': session must complete');
  assert.equal(session.finalResult.fallbackUsed, true, label + ': fallback must be used when Sandbox is absent');
  assert.equal(session.finalResult.completionState, 'deep_static_fallback', label + ': must use deep static fallback');
  assert.equal(session.finalResult.sandboxStarted, false, label + ': sandbox must not be claimed as started');
  assert.equal(session.finalResult.sampleExecutionStarted, false, label + ': sample execution must not be claimed');
  assert.equal(session.finalResult.dynamicAnalysisUnavailable, true, label + ': dynamic limitation must be explicit');

  const local = session.finalResult.localResult;
  assert(local && local.sourceIdentity && local.sourceIdentity.revalidated === true, label + ': file identity must be revalidated');
  assert(local.engineResult && local.engineResult.peValid === true, label + ': PE engine must fully validate the sample');

  const engines = engineMap(local);
  assert(engines.yara_x, label + ': YARA-X evidence missing');
  assert(engines.capa, label + ': capa evidence missing');
  assert.equal(engines.yara_x.status, 'no_match', label + ': benign fixture must not match MalGuard YARA rules');
  assert.equal(engines.capa.status, 'complete', label + ': capa must execute to completion');
  assert(session.finalResult.fusion && session.finalResult.fusion.layers.independentEngines.completed >= 2,
    label + ': at least two independent engines must complete');

  assert.notEqual(session.finalResult.verdict, 'inconclusive',
    label + ': full static + independent engine coverage must not collapse to INCONCLUSIVE merely because Sandbox is absent');
  assert.notEqual(session.finalResult.verdict, 'malicious',
    label + ': benign fixture must not be classified malicious');
  assert.notEqual(session.finalResult.fusion.basis, 'insufficient_independent_engine_coverage',
    label + ': independent engine coverage is present');
  assert.equal(session.finalResult.fusion.safeClaim.absoluteGuarantee, false,
    label + ': even SAFE must remain bounded, never absolute');

  console.log(JSON.stringify({
    label,
    verdict:session.finalResult.verdict,
    basis:session.finalResult.fusion.basis,
    riskScore:session.finalResult.fusion.riskScore,
    independentCompleted:session.finalResult.fusion.layers.independentEngines.completed,
    yara:engines.yara_x.status,
    capa:engines.capa.status,
    sandboxStarted:session.finalResult.sandboxStarted,
    executionStarted:session.finalResult.sampleExecutionStarted,
  }));
}

async function runStarvationCase(scanner, filePath) {
  const oldYara = process.env.MALGUARD_YARAX_BIN;
  const oldCapa = process.env.MALGUARD_CAPA_BIN;
  const oldFloss = process.env.MALGUARD_FLOSS_BIN;
  const oldClam = process.env.MALGUARD_CLAM_BIN;
  process.env.MALGUARD_YARAX_BIN = 'Z:\\definitely-missing\\yr.exe';
  process.env.MALGUARD_CAPA_BIN = 'Z:\\definitely-missing\\capa.exe';
  process.env.MALGUARD_FLOSS_BIN = 'Z:\\definitely-missing\\floss.exe';
  process.env.MALGUARD_CLAM_BIN = 'Z:\\definitely-missing\\clamscan.exe';
  try {
    const manager = new ModelScanPipelineManager({ scanner, sandbox:noSandbox() });
    const started = manager.start(filePath, 'pro', { allowCloudFallback:false, allowAiEvidence:false });
    const session = await waitFor(manager, started.id);

    assert.equal(session.finalResult.fallbackUsed, true);
    assert.equal(session.finalResult.sandboxStarted, false);
    assert.equal(session.finalResult.sampleExecutionStarted, false);
    assert.equal(session.finalResult.verdict, 'inconclusive',
      'when Sandbox is absent AND independent engine coverage is genuinely starved, Pro must fail closed');
    assert.equal(session.finalResult.fusion.basis, 'insufficient_independent_engine_coverage',
      'INCONCLUSIVE must have a concrete coverage reason');

    const engines = engineMap(session.finalResult.localResult);
    assert.equal(engines.yara_x.status, 'unavailable');
    assert.equal(engines.capa.status, 'unavailable');
    assert(session.finalResult.fusion.layers.independentEngines.completed < 2);

    console.log(JSON.stringify({
      label:'forced-engine-starvation',
      verdict:session.finalResult.verdict,
      basis:session.finalResult.fusion.basis,
      independentCompleted:session.finalResult.fusion.layers.independentEngines.completed,
      yara:engines.yara_x.status,
      capa:engines.capa.status,
      sandboxStarted:session.finalResult.sandboxStarted,
    }));
  } finally {
    if (oldYara === undefined) delete process.env.MALGUARD_YARAX_BIN; else process.env.MALGUARD_YARAX_BIN = oldYara;
    if (oldCapa === undefined) delete process.env.MALGUARD_CAPA_BIN; else process.env.MALGUARD_CAPA_BIN = oldCapa;
    if (oldFloss === undefined) delete process.env.MALGUARD_FLOSS_BIN; else process.env.MALGUARD_FLOSS_BIN = oldFloss;
    if (oldClam === undefined) delete process.env.MALGUARD_CLAM_BIN; else process.env.MALGUARD_CLAM_BIN = oldClam;
  }
}

(async () => {
  if (process.platform !== 'win32') {
    throw new Error('TSH Pro real-scan validation must run on Windows');
  }
  const source = process.argv[2];
  assert(source && fs.existsSync(source), 'path to a real benign PE fixture is required');

  const temp = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'malguard-tsh-pro-'));
  try {
    const asi = path.join(temp, 'tsh-pro-benign.asi');
    const dll = path.join(temp, 'tsh-pro-benign.dll');
    const exe = path.join(temp, 'tsh-pro-benign.exe');
    await fs.promises.copyFile(source, asi);
    await fs.promises.copyFile(source, dll);
    await fs.promises.copyFile(source, exe);

    const scanner = new ScannerBridge();

    // Hard question #1: GTA plugins cannot be executed directly. Can Pro still scan them?
    await runNoSandboxCase(scanner, asi, 'ASI / Sandbox unsupported');
    await runNoSandboxCase(scanner, dll, 'DLL / Sandbox unsupported');

    // Hard question #2: even an executable loses Sandbox. Does Pro still use real local evidence?
    await runNoSandboxCase(scanner, exe, 'EXE / Sandbox unavailable');

    // Hard question #3: prove INCONCLUSIVE is reserved for truly insufficient evidence.
    await runStarvationCase(scanner, asi);

    console.log('✓ TSH PRO: real Windows scan, real YARA-X+capa, no-Sandbox fallback, and evidence-starvation fail-closed PASS');
  } finally {
    await fs.promises.rm(temp, { recursive:true, force:true });
  }
})().catch(error => {
  console.error(error && error.stack || error);
  process.exit(1);
});
