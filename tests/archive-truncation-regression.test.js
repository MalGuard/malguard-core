'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { webcrypto } = require('crypto');

const ROOT = path.resolve(__dirname, '..');
const FIXTURE = path.join(__dirname, 'fixtures', 'gtav-benign-scripts.zip');

class FileLike {
  constructor(name, bytes) {
    this.name = name;
    this.bytes = Buffer.from(bytes);
    this.size = this.bytes.length;
  }
  async arrayBuffer() {
    return this.bytes.buffer.slice(this.bytes.byteOffset, this.bytes.byteOffset + this.bytes.byteLength);
  }
  slice(start, end) {
    return new FileLike(this.name, this.bytes.subarray(start || 0, end == null ? this.bytes.length : end));
  }
}

function loadInspector() {
  const context = { console, TextDecoder, TextEncoder, crypto: webcrypto, performance, setTimeout, clearTimeout, ReadableStream, DecompressionStream, window: null };
  context.window = context;
  vm.createContext(context);
  for (const file of ['gta-mod-detector.js', 'archive-inspector.js']) {
    vm.runInContext(fs.readFileSync(path.join(ROOT, file), 'utf8'), context, { filename: file });
  }
  return context.ArchiveInspector;
}

(async () => {
  const original = fs.readFileSync(FIXTURE);
  const eocdOffset = original.length - 22;
  assert.equal(original.readUInt32LE(eocdOffset), 0x06054b50, 'benign fixture should end with a ZIP EOCD record');
  assert.equal(original.readUInt16LE(eocdOffset + 20), 0, 'benign fixture should have no EOCD comment');

  const inspector = loadInspector();
  const validResult = await inspector.inspect(new FileLike('gtav-benign-scripts.zip', original));
  console.log(`Valid benign fixture inspectionStatus: ${validResult.inspectionStatus}`);
  assert.equal(validResult.inspectionStatus, 'completed', 'valid benign fixture should complete inspection');
  assert.equal(validResult.inspectionSucceeded, true, 'valid fixture inspection should succeed');

  const truncated = original.subarray(0, eocdOffset);
  const malformedResult = await inspector.inspect(new FileLike('truncated-benign-fixture.zip', truncated));
  assert.equal(malformedResult.archiveType, 'zip');
  assert.equal(malformedResult.inspectionStatus, 'malformed_archive');
  assert.equal(malformedResult.inspectionSucceeded, false);
  assert.match(malformedResult.warnings.join(' '), /eocd_not_found/);

  console.log('Truncated benign fixture was rejected as malformed without an uncaught exception.');
})().catch(error => {
  console.error(error.stack || error);
  process.exitCode = 1;
});
