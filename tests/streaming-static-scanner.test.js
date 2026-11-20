'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const crypto = require('node:crypto');
const MiB = 1024 * 1024;
const context = { console, TextDecoder, Uint8Array, Uint32Array, DataView };
context.self = context;
vm.createContext(context);
vm.runInContext(fs.readFileSync(path.join(__dirname, '../streaming-static-scanner.js'), 'utf8'), context);
const scanner = context.MalGuardStreamingScanner;
const marker = 'process_hollowing';

class FileLike {
  constructor(name, bytes, declaredSize = bytes.length) {
    this.name = name;
    this.bytes = bytes;
    this.size = declaredSize;
  }
  slice(start, end) {
    const part = this.bytes.subarray(start, end);
    return {
      size: part.length,
      async arrayBuffer() {
        return part.buffer.slice(part.byteOffset, part.byteOffset + part.byteLength);
      }
    };
  }
}
function expectedSha(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}
context.loadRules = async () => ({
  status: 'official',
  suspicious_strings: [{ id: 'STR-033', category: 'process_injection',
    pattern: marker, severity: 'high', weight: 20 }],
  gta_markers: []
});
async function scanBytes(bytes, progress = []) {
  const f = new FileLike('fixture.dll', bytes);
  return scanner.scan(f, { onProgress: p => progress.push(p) });
}
async function run() {
  const h = new scanner.StreamingSha256();
  assert.equal(h.digestHex(), expectedSha(Buffer.alloc(0)), 'Empty SHA-256 mismatch');
  for (const size of [1, 55, 56, 63, 64, 65, 1024, 4000001]) {
    const bytes = crypto.randomBytes(size);
    const hasher = new scanner.StreamingSha256();
    for (let i = 0; i < bytes.length; i += 7919) hasher.update(bytes.subarray(i, i + 7919));
    assert.equal(hasher.digestHex(), expectedSha(bytes), 'SHA mismatch for bytes ' + size);
  }
  let progress = [];
  let bytes = Buffer.alloc(16 * MiB, 0);
  bytes.write(marker, 10 * MiB);
  let result = await scanBytes(bytes, progress);
  assert.equal(result.sha256, expectedSha(bytes));
  assert.equal(result.bytesScanned, bytes.length);
  assert.equal(result.finalVerdict, 'suspicious', 'Middle marker must not be missed');
  assert.equal(result.findings[0].rule, 'STR-033');
  assert.equal(result.coverage, 'complete_string_scan_only');
  assert.equal(progress.length, 1, '16 MiB file must generate one 10 MiB report');
  assert.equal(progress[0].scannedBytes, 10 * MiB);
  assert.equal(progress[0].provisional, true);

  bytes = Buffer.alloc(8 * MiB, 0);
  bytes.write(marker, 4 * MiB - 4);
  result = await scanBytes(bytes);
  assert.equal(result.finalVerdict, 'suspicious', 'ASCII marker spanning boundary missed');

  bytes = Buffer.alloc(8 * MiB, 0);
  bytes.write(marker, 4 * MiB - 8, 'utf16le');
  result = await scanBytes(bytes);
  assert.equal(result.finalVerdict, 'suspicious', 'UTF-16 marker spanning boundary missed');
  assert.equal(result.findings[0].encoding, 'UTF-16LE');

  bytes = Buffer.alloc(12 * MiB, 0);
  result = await scanBytes(bytes);
  assert.equal(result.finalVerdict, 'inconclusive', 'No textual indicators cannot imply SAFE');

  await assert.rejects(() => scanner.scan(new FileLike('oversize.dll', Buffer.alloc(1), 1024 * MiB + 1)),
    e => e.code === 'WORKER_INPUT_TOO_LARGE');
  await assert.rejects(() => scanner.scan(new FileLike('boundary.dll', Buffer.alloc(1), 1024 * MiB)),
    e => e.code === 'CHUNK_READ_MISMATCH', 'Truncated virtual 1-GiB input must fail closed');

  console.log('✓ Bounded scanner: SHA-256, marker boundaries, progress, incomplete verdicts and size guards passed');
}
run().catch(e => { console.error(e.stack || e); process.exitCode = 1; });
