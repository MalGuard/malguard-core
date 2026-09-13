'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const vm = require('vm');
const { webcrypto } = require('crypto');
const { ScannerBridge } = require('../desktop-app/scanner-bridge.js');

const ROOT = path.resolve(__dirname, '..');
const RULES = JSON.parse(fs.readFileSync(path.join(ROOT, 'rules.json'), 'utf8'));

function load(c, name) {
  vm.runInContext(fs.readFileSync(path.join(ROOT, name), 'utf8'), c, { filename: name });
}

function engineContext(cryptoImpl = webcrypto) {
  const c = {
    console,
    window: null,
    crypto: cryptoImpl,
    TextDecoder,
    TextEncoder,
    performance,
    setTimeout,
    clearTimeout,
    fetch: async () => ({ ok: true, status: 200, json: async () => JSON.parse(JSON.stringify(RULES)) }),
  };
  c.window = c;
  vm.createContext(c);
  load(c, 'engine.js');
  return c;
}

function appContext() {
  const c = { console, window: null };
  c.window = c;
  vm.createContext(c);
  load(c, 'malguard-contract.js');
  return c;
}

function fileLike(name, bytes, declaredSize = null) {
  const data = Uint8Array.from(bytes);
  return {
    name,
    size: declaredSize == null ? data.byteLength : declaredSize,
    async arrayBuffer() { return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength); },
    slice(start, end) { return fileLike(name, data.slice(start || 0, end == null ? data.length : end)); },
  };
}

(async () => {
  // 1) Rules cannot configure negative/oversized thresholds that turn arbitrary scores SAFE.
  let c = engineContext();
  const badNegative = JSON.parse(JSON.stringify(RULES));
  badNegative.safe_threshold = -1;
  badNegative.suspicious_threshold = -10;
  let errors = vm.runInContext(`validateRules(${JSON.stringify(badNegative)})`, c);
  assert.ok(errors.length > 0, 'negative thresholds were accepted');

  const badMax = JSON.parse(JSON.stringify(RULES));
  badMax.max_score = 101;
  errors = vm.runInContext(`validateRules(${JSON.stringify(badMax)})`, c);
  assert.ok(errors.length > 0, 'max_score > 100 was accepted');

  const badAboveMax = JSON.parse(JSON.stringify(RULES));
  badAboveMax.max_score = 50;
  badAboveMax.safe_threshold = 80;
  errors = vm.runInContext(`validateRules(${JSON.stringify(badAboveMax)})`, c);
  assert.ok(errors.length > 0, 'threshold above max_score was accepted');

  // 2) Declared size and actual bytes must match. A lying File-like object cannot reach SAFE.
  let r = await c.scanFile(fileLike('mismatch.asi', [0x4d, 0x5a, 0x00, 0x00], 2));
  assert.equal(r.verdict, 'invalid');
  assert.equal(r.errorCode, 'READ_SIZE_MISMATCH');

  // 3) SHA-256 is a mandatory identity primitive. Digest failure must fail closed before PE analysis.
  const failingCrypto = { subtle: { digest: async () => { throw new Error('synthetic digest failure'); } } };
  c = engineContext(failingCrypto);
  r = await c.scanFile(fileLike('hashfail.asi', [0x4d, 0x5a, 0x00, 0x00]));
  assert.equal(r.verdict, 'invalid');
  assert.equal(r.errorCode, 'HASH_FAILED');

  // 4) Runtime/module version mismatch cannot result in SAFE.
  c = appContext();
  c.MalGuardEngine = { version: '0.0.0' };
  c.scanFile = async () => ({ verdict: 'safe', score: 100, rulesStatus: 'official', hash: '0'.repeat(64), engineVersion: '2.2.2' });
  load(c, 'app.js');
  r = await c.scanFileWithMode({ name: 'x.asi', size: 1 }, 'free');
  assert.equal(r.finalVerdict, 'inconclusive');
  assert.equal(r.hardeningError, 'runtime_module_version_mismatch');

  // 5) Even with a correct runtime module version, a malformed SAFE engine envelope is rejected.
  c = appContext();
  c.MalGuardEngine = { version: '2.2.2' };
  c.scanFile = async () => ({ verdict: 'safe', score: 100, rulesStatus: 'official', hash: null, engineVersion: '2.2.2' });
  load(c, 'app.js');
  r = await c.scanFileWithMode({ name: 'x.asi', size: 1 }, 'free');
  assert.equal(r.finalVerdict, 'inconclusive');
  assert.equal(r.hardeningError, 'engine_result_hash_invalid');

  // 6) A present-but-incompatible secondary Pro module is never trusted.
  c = appContext();
  c.MalGuardEngine = { version: '2.2.2' };
  c.GtaModDetector = { version: '1.0.0', analyze: async () => ({ route: 'ENGINE', modType: 'plugin' }) };
  c.MultiLayerSecurity = { version: '9.9.9', analyze: () => ({ finalVerdict: 'safe' }) };
  c.scanFile = async () => ({ verdict: 'safe', score: 100, rulesStatus: 'official', hash: '0'.repeat(64), engineVersion: '2.2.2' });
  load(c, 'app.js');
  r = await c.scanFileWithMode({ name: 'x.asi', size: 1 }, 'pro');
  assert.equal(r.finalVerdict, 'inconclusive');
  assert.equal(r.hardeningError, 'runtime_module_version_mismatch');
  assert.equal(r.runtimeAttestation.module, 'multiLayer');

  // 7) Desktop path scanning revalidates the exact content after scan completion.
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'malguard-scanner-acceptance-'));
  try {
    const target = path.join(temp, 'race.asi');
    fs.writeFileSync(target, Buffer.from('initial bytes'));
    const bridge = new ScannerBridge();
    bridge.scanBuffer = async () => {
      await new Promise(resolve => setTimeout(resolve, 80));
      return { resultSchemaVersion: '1.0.0', finalVerdict: 'safe', mode: 'pro' };
    };
    setTimeout(() => fs.writeFileSync(target, Buffer.from('changed bytes')), 20);
    r = await bridge.scanPath(target, 'pro');
    assert.equal(r.finalVerdict, 'inconclusive');
    assert.equal(r.hardeningError, 'desktop_file_changed_during_scan');

    // 8) Symbolic-link scan targets are rejected instead of following a potentially swapped target.
    const real = path.join(temp, 'real.asi');
    const link = path.join(temp, 'link.asi');
    fs.writeFileSync(real, Buffer.from('real'));
    try {
      fs.symlinkSync(real, link);
      await assert.rejects(() => bridge.scanPath(link, 'pro'), err => err && err.code === 'SCAN_TARGET_SYMLINK');
    } catch (error) {
      if (!error || !['EPERM', 'EACCES', 'ENOSYS'].includes(error.code)) throw error;
    }
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }

  console.log('✓ Scanner Core acceptance: rules/hash/size/runtime-envelope/path-identity fail-closed checks passed');
})().catch(error => {
  console.error(error && error.stack ? error.stack : error);
  process.exit(1);
});
