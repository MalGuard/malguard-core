'use strict';
const assert = require('assert');
const { ALLOWED_FIXTURE, createIsolationJob } = require('../cloud-sandbox/job-policy');

const good = createIsolationJob(ALLOWED_FIXTURE);
assert.equal(good.accepted, true);
assert.equal(good.isolation.ephemeral, true);
assert.equal(good.isolation.networkPolicy, 'deny-all');
assert.deepEqual(good.isolation.publicPorts, []);
assert.deepEqual(good.isolation.secrets, []);
assert.equal(good.isolation.hostFallback, false);
assert.equal(good.isolation.destroyAfterRun, true);
assert.equal(good.isolation.timeoutMs, 30000);

const unknown = createIsolationJob(Buffer.from('MZ-not-a-real-executable'));
assert.equal(unknown.accepted, false);
assert.equal(unknown.reason, 'phase1-safe-fixtures-only');

console.log('✓ Cloud Sandbox Phase 1 policy: safe fixture only, ephemeral, deny-all egress, no secrets, no host fallback, teardown required PASS');
