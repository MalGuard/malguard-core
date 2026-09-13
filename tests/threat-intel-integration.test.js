'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { ScannerBridge } = require('../desktop-app/scanner-bridge.js');

const FIXTURE = path.join(__dirname, 'corpus', 'benign-config-read.lua');

(async () => {
  let observedHash = null;
  const known = new ScannerBridge({
    threatIntel: {
      async lookupSha256(hash) {
        observedHash = hash;
        return { provider: 'malwarebazaar', status: 'known_malicious', source: 'cache', hash, signature: 'UnitTestFamily' };
      },
    },
  });
  const result = await known.scanPath(FIXTURE, 'pro');
  assert.equal(result.finalVerdict, 'malicious', 'exact known-malicious hash must override local SAFE');
  assert.equal(result.reputationOverride, 'malwarebazaar_exact_sha256');
  assert.equal(observedHash, result.sourceIdentity.sha256);
  assert(result.reputationEvidence.some(x => x.rule === 'MALWAREBAZAAR-EXACT-SHA256'));

  const unavailable = new ScannerBridge({
    threatIntel: { async lookupSha256(hash) { return { provider: 'malwarebazaar', status: 'unavailable', source: 'live', hash, reason: 'timeout' }; } },
  });
  const local = await unavailable.scanPath(FIXTURE, 'pro');
  assert.equal(local.finalVerdict, 'safe', 'reputation outage must not erase a complete local static analysis');
  assert.equal(local.threatIntel.status, 'unavailable');
  assert.notEqual(local.reputationOverride, 'malwarebazaar_exact_sha256');

  const disabled = new ScannerBridge();
  const localOnly = await disabled.scanPath(FIXTURE, 'pro');
  assert.equal(localOnly.threatIntel.status, 'disabled');

  console.log('✓ MalwareBazaar reputation integrates additively without false SAFE from reputation misses/outages PASS');
})().catch(error => { console.error(error); process.exit(1); });
