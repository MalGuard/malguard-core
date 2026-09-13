'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { webcrypto } = require('crypto');

const ROOT = path.resolve(__dirname, '..');
const CORPUS = path.join(__dirname, 'corpus');

class FileLike {
  constructor(name, bytes) {
    this.name = name;
    this._bytes = Buffer.from(bytes);
    this.size = this._bytes.length;
  }
  async arrayBuffer() {
    return this._bytes.buffer.slice(this._bytes.byteOffset, this._bytes.byteOffset + this._bytes.byteLength);
  }
  slice(start, end) {
    return new FileLike(this.name, this._bytes.subarray(start || 0, end == null ? this._bytes.length : end));
  }
}

function makeContext() {
  const context = {
    console,
    TextDecoder,
    TextEncoder,
    crypto: webcrypto,
    performance,
    setTimeout,
    clearTimeout,
    window: null,
  };
  context.window = context;
  vm.createContext(context);
  return context;
}

function load(context, filename) {
  vm.runInContext(fs.readFileSync(path.join(ROOT, filename), 'utf8'), context, { filename });
}

(async () => {
  const context = makeContext();
  load(context, 'script-analyzer.js');
  const manifest = JSON.parse(fs.readFileSync(path.join(CORPUS, 'manifest.json'), 'utf8'));
  let passed = 0;

  for (const test of manifest) {
    const bytes = fs.readFileSync(path.join(CORPUS, test.file));
    const result = await context.ScriptAnalyzer.analyze(new FileLike(test.file, bytes));

    assert.ok(
      test.allowedVerdicts.includes(result.verdict),
      `${test.file}: expected ${test.allowedVerdicts.join('/')} but got ${result.verdict}`
    );

    if (test.mustNot) {
      assert.notEqual(result.verdict, test.mustNot, `${test.file}: forbidden verdict ${test.mustNot}`);
    }

    if (test.category) {
      const evidence = Array.isArray(result.evidence) ? result.evidence : [];
      assert.ok(
        evidence.some(item => item.category === test.category),
        `${test.file}: missing expected evidence category ${test.category}`
      );
    }

    if (test.errorCode) {
      assert.equal(result.errorCode, test.errorCode, `${test.file}: unexpected error code`);
    }

    passed++;
  }

  console.log(`✓ Regression corpus: ${passed}/${manifest.length} cases passed`);
})().catch((err) => {
  console.error(err && err.stack ? err.stack : err);
  process.exit(1);
});
