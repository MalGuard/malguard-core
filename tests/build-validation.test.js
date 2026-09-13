'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { webcrypto } = require('crypto');

const ROOT = path.resolve(__dirname, '..');
const source = name => fs.readFileSync(path.join(ROOT, name), 'utf8');

// 1) V8 syntax parse every project/test JS file.
const jsFiles = [];
(function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(p);
    else if (entry.isFile() && p.endsWith('.js')) jsFiles.push(p);
  }
})(ROOT);
for (const file of jsFiles) new vm.Script(fs.readFileSync(file, 'utf8'), { filename: file });

// 2) Rules + regression corpus metadata.
JSON.parse(source('rules.json'));
const manifest = JSON.parse(source('tests/corpus/manifest.json'));
assert.ok(manifest.length >= 50, 'Hardening regression corpus unexpectedly small');
for (const item of manifest) {
  assert.ok(fs.existsSync(path.join(ROOT, 'tests/corpus', item.file)), `Missing corpus file: ${item.file}`);
}

// 3) HTML load order and worker-only UI path.
const html = source('index.html');
const scripts = [...html.matchAll(/<script\s+src="([^"]+)"\s*><\/script>/g)].map(m => m[1]);
for (const ref of scripts) assert.ok(fs.existsSync(path.join(ROOT, ref)), `Missing HTML script: ${ref}`);
assert.ok(scripts.includes('malguard-contract.js'));
assert.ok(scripts.indexOf('malguard-contract.js') < scripts.indexOf('engine.js'), 'contract must load before analyzers');
assert.ok(scripts.indexOf('scan-worker-client.js') > scripts.indexOf('app.js'), 'worker client must load after app');
assert.ok(scripts.indexOf('self-test.js') > scripts.indexOf('scan-worker-client.js'), 'self-test must load after worker client');
assert.ok(html.includes('await scanFileInWorker(selectedFile, currentMode, {'), 'UI is not routed through worker scanner');
assert.ok(html.includes('currentScanAbortController.signal'), 'UI does not provide cancellation signal');
assert.ok(!source('scan-worker-client.js').includes('main_thread_fallback'), 'Production worker client still contains silent main-thread fallback');

// 4) Inline scripts parse.
const inlineBlocks = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)]
  .filter(m => !/\bsrc=/.test(m[0]))
  .map(m => m[1]);
for (let i = 0; i < inlineBlocks.length; i++) new vm.Script(inlineBlocks[i], { filename: `index-inline-${i}.js` });

// 5) Classic scripts coexist without lexical collisions and expose expected APIs.
const context = {
  console,
  TextDecoder,
  TextEncoder,
  crypto: webcrypto,
  performance,
  setTimeout,
  clearTimeout,
  ReadableStream,
  DecompressionStream,
  Blob,
  Response,
  AbortController,
  fetch: async () => new Response('{}', { status: 404 }),
  window: null,
};
context.window = context;
vm.createContext(context);
for (const filename of [
  'malguard-contract.js', 'engine.js', 'multilayer.js', 'gta-mod-detector.js', 'archive-inspector.js',
  'archive-entry-reader.js', 'script-analyzer.js', 'app.js', 'scan-worker-client.js', 'self-test.js',
]) vm.runInContext(source(filename), context, { filename });

assert.equal(context.MalGuardContract.contractVersion, '1.1.0');
assert.equal(context.MalGuardContract.workerProtocol, 2);
assert.equal(context.MalGuardEngine.version, '2.2.2');
assert.equal(context.MalGuardApp.version, '1.5.1');
assert.equal(context.MalGuardWorkerScanner.version, '1.2.0');
assert.equal(typeof context.scanFileWithMode, 'function');
assert.equal(typeof context.scanFileInWorker, 'function');
assert.equal(typeof context.MalGuardSelfTest.run, 'function');

console.log(`✓ Build validation: ${jsFiles.length} JS files, ${manifest.length} corpus cases, contract/load-order/isolation PASS`);
