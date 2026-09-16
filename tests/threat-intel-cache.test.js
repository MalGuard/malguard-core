'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { ThreatIntelCache } = require('../desktop-app/threat-intel/cache-store.js');

(async () => {
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'malguard-ti-cache-'));
  const file = path.join(dir, 'cache.json');
  const hash = 'c'.repeat(64);
  const cache = new ThreatIntelCache({ filePath: file, foundTtlMs: 1000, notFoundTtlMs: 100, maxEntries: 64 });
  assert.equal((await cache.load()).ok, true);
  await cache.put({ hash, status: 'known_malicious', signature: 'UnitTest', tags: ['x'] }, 1000);
  const got = await cache.get(hash, 1500);
  assert(got);
  assert.equal(got.status, 'known_malicious');
  assert.equal(got.metadata.signature, 'UnitTest');
  assert.equal(await cache.get(hash, 2501), null, 'expired known-malicious cache must not be trusted forever');

  const batchA = 'e'.repeat(64);
  const batchB = 'f'.repeat(64);
  const batch = await cache.putMany([
    { hash: batchA, status: 'known_malicious', signature: 'RecentA', fileType: 'dll', fileName: 'a.dll', fileSize: 11 },
    { hash: batchB, status: 'known_malicious', signature: 'RecentB', fileType: 'exe', fileName: 'b.exe', fileSize: 22 },
  ], 2600);
  assert.equal(batch.ok, true);
  assert.equal(batch.added, 2);
  assert.equal((await cache.get(batchA, 2700)).metadata.fileName, 'a.dll');
  assert.equal((await cache.get(batchB, 2700)).metadata.fileSize, 22);

  const missHash = 'd'.repeat(64);
  await cache.put({ hash: missHash, status: 'not_found' }, 3000);
  assert.equal((await cache.get(missHash, 3050)).status, 'not_found');
  assert.equal(await cache.get(missHash, 3200), null);

  const rejectedBatch = await cache.putMany([{ hash: 'invalid', status: 'known_malicious' }], 3300);
  assert.equal(rejectedBatch.ok, false);
  assert.equal(rejectedBatch.reason, 'non_cacheable_batch_result');

  await fs.promises.writeFile(file, '{broken json', 'utf8');
  const corrupt = new ThreatIntelCache({ filePath: file });
  const loaded = await corrupt.load();
  assert.equal(loaded.ok, false);
  assert.equal(loaded.corrupt, true);
  assert.equal(await corrupt.get(hash), null, 'corrupt cache must not manufacture reputation');

  await fs.promises.rm(dir, { recursive: true, force: true });
  console.log('✓ Threat-intel cache TTL, atomic batch persistence and corruption fail-closed behavior PASS');
})().catch(error => { console.error(error); process.exit(1); });
