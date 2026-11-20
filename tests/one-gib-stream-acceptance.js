'use strict';

// One-off heavy acceptance: 1-GiB sparse benign DLL-shaped file.
// Do not add to run-all: this is intentionally a resource-intensive regression.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { performance } = require('node:perf_hooks');
const { ScannerBridge } = require('../desktop-app/scanner-bridge.js');

const MiB = 1024 * 1024;
const SIZE = 1024 * MiB;
const MARKER = Buffer.from('process_hollowing');
const MARKER_AT = 700 * MiB + 157;
const RSS_LIMIT = 768 * MiB;
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'malguard-1gib-'));
const filename = path.join(temporary, '1gib-sparse.dll');
let memorySample = process.memoryUsage().rss;
const ticker = setInterval(() => {
  memorySample = Math.max(memorySample, process.memoryUsage().rss);
}, 25);

(async () => {
  const fd = fs.openSync(filename, 'w');
  try {
    fs.ftruncateSync(fd, SIZE);
    fs.writeSync(fd, MARKER, 0, MARKER.length, MARKER_AT);
  } finally {
    fs.closeSync(fd);
  }

  const bridge = new ScannerBridge();
  const reports = [];
  const start = performance.now();
  const result = await bridge.scanPath(filename, 'pro', {
    reportMode: 'detailed',
    onProgress: event => {
      if (event.scannedBytes % (10 * MiB) !== 0) {
        throw new Error('Progress checkpoint is not an exact 10-MiB boundary.');
      }
      reports.push(event);
    }
  });
  const durationMs = performance.now() - start;
  clearInterval(ticker);
  memorySample = Math.max(memorySample, process.memoryUsage().rss);

  assert.equal(result.finalVerdict, 'suspicious', JSON.stringify(result).slice(0, 1800));
  assert.equal(result.streamingResult.fileSize, SIZE);
  assert.equal(result.streamingResult.bytesScanned, SIZE);
  assert.equal(result.sourceIdentity.revalidated, true);
  assert.equal(reports.length, 102, 'Expected 102 completed 10-MiB reports');
  assert.equal(reports[0].scannedBytes, 10 * MiB);
  assert.equal(reports[reports.length - 1].scannedBytes, 1020 * MiB);
  assert.equal(reports.every(p => p.provisional === true), true);
  assert.ok(result.streamingResult.findings.some(f => f.rule === 'STR-033'));

  // Independent Node implementation; read file in bounded blocks.
  const expected = createHash('sha256');
  const confirmHandle = fs.openSync(filename, 'r');
  const slab = Buffer.alloc(4 * MiB);
  try {
    for (let pos = 0; pos < SIZE; pos += slab.length) {
      const n = fs.readSync(confirmHandle, slab, 0, Math.min(slab.length, SIZE - pos), pos);
      assert.equal(n, Math.min(slab.length, SIZE - pos));
      expected.update(slab.subarray(0, n));
    }
  } finally {
    fs.closeSync(confirmHandle);
  }
  assert.equal(result.streamingResult.sha256, expected.digest('hex'));
  assert.ok(memorySample < RSS_LIMIT, 'Sampled RSS exceeded 768 MiB: ' + memorySample);

  console.log(JSON.stringify({
    outcome: 'PASS',
    bytesScanned: SIZE,
    chunkSize: 4 * MiB,
    checkpoints: reports.length,
    markerAt: MARKER_AT,
    verdict: result.finalVerdict,
    sha256Verified: true,
    sampledPeakRssMiB: Number((memorySample / MiB).toFixed(1)),
    durationSeconds: Number((durationMs / 1000).toFixed(1)),
    structuralScan: 'not covered',
  }, null, 2));
})().catch(error => {
  clearInterval(ticker);
  console.error(error.stack || error);
  process.exitCode = 1;
}).finally(() => {
  fs.rmSync(temporary, { recursive: true, force: true });
});
