'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { ThreatIntelService } = require('../desktop-app/threat-intel/service.js');
const { ThreatIntelCache } = require('../desktop-app/threat-intel/cache-store.js');

(async () => {
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'malguard-ti-feed-'));
  const cache = new ThreatIntelCache({ filePath: path.join(dir, 'cache.json') });
  const hashA = '1'.repeat(64);
  const hashB = '2'.repeat(64);
  let recentCalls = 0;
  let lookupCalls = 0;

  const client = {
    async listRecent(selector) {
      recentCalls++;
      assert.equal(selector, '100');
      return {
        provider: 'malwarebazaar',
        status: 'ok',
        selector,
        metadataOnly: true,
        samplesDownloaded: false,
        entries: [
          { provider: 'malwarebazaar', status: 'known_malicious', hash: hashA, signature: 'FeedA', fileType: 'dll', fileName: 'a.dll', fileSize: 10, tags: [] },
          { provider: 'malwarebazaar', status: 'known_malicious', hash: hashB, signature: 'FeedB', fileType: 'exe', fileName: 'b.exe', fileSize: 20, tags: [] },
        ],
        count: 2,
      };
    },
    async lookupSha256(hash) {
      lookupCalls++;
      return { provider: 'malwarebazaar', status: 'not_found', hash };
    },
  };

  const credentials = {
    async status() { return { configured: true, source: 'unit-test' }; },
    async getAuthKey() { return 'not-used-in-mock'; },
  };

  const service = new ThreatIntelService({ client, cache, credentials, recentSyncIntervalMs: 60 * 1000 });
  const synced = await service.syncRecent();
  assert.equal(synced.status, 'ok');
  assert.equal(synced.count, 2);
  assert.equal(synced.metadataOnly, true);
  assert.equal(synced.samplesDownloaded, false);
  assert.equal(recentCalls, 1);

  const cached = await service.lookupSha256(hashA, { syncRecent: false });
  assert.equal(cached.status, 'known_malicious');
  assert.equal(cached.source, 'cache');
  assert.equal(cached.signature, 'FeedA');
  assert.equal(lookupCalls, 0, 'recent feed cache hit must avoid redundant per-hash lookup');

  const status = await service.status();
  assert.equal(status.recentFeed.status, 'ok');
  assert.equal(status.recentFeed.count, 2);
  assert(status.cache.entries >= 2);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(recentCalls, 1, 'status must not trigger a duplicate background sync immediately after manual sync');
  assert.equal(service._recentSyncPromise, null, 'no background cache write should remain after recent manual sync');

  const auto = service.startAutoSync();
  assert.equal(auto.ok, true);
  assert.equal(service._autoSyncTimer != null, true);
  const autoStatus = await service.status();
  assert.equal(autoStatus.recentFeed.autoSyncRunning, true);
  assert.equal(autoStatus.recentFeed.autoSyncIntervalMs, 60 * 1000);
  service.stopAutoSync();
  assert.equal(service._autoSyncTimer, null);

  await fs.promises.rm(dir, { recursive: true, force: true });
  console.log('✓ Threat-intel recent metadata sync populates cache without duplicate post-sync background writes');
})().catch(error => { console.error(error); process.exit(1); });
