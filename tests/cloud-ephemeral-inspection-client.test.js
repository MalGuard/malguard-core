'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const {
  CloudEphemeralInspectionClient,
  DEFAULT_ENDPOINT,
  MAX_CLOUD_INSPECTION_BYTES,
} = require('../desktop-app/sandbox/cloud-ephemeral-inspection.js');

(async () => {
  assert.match(DEFAULT_ENDPOINT, /^https:\/\//);
  assert.equal(MAX_CLOUD_INSPECTION_BYTES, 8 * 1024 * 1024);

  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'malguard-cloud-inspection-'));
  try {
    const sample = path.join(dir, 'sample.dll');
    const bytes = Buffer.from('MZ synthetic cloud inspection fixture');
    await fs.promises.writeFile(sample, bytes);
    const sha256 = crypto.createHash('sha256').update(bytes).digest('hex');

    let posted = null;
    const client = new CloudEphemeralInspectionClient({
      endpoint: 'https://sandbox.example.test/api/inspect',
      fetchImpl: async (url, options) => {
        posted = { url, options };
        return {
          ok: true,
          status: 200,
          json: async () => ({
            ok: true,
            report: { bytes: bytes.length, sha256, type: 'windows-pe' },
            isolation: {
              ephemeral: true,
              networkPolicy: 'deny-all',
              hostFallback: false,
              destroyAfterRun: true,
              execution: 'inspection-only',
            },
          }),
        };
      },
    });

    const result = await client.inspect(sample);
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.equal(result.mode, 'cloud_ephemeral_inspection');
    assert.equal(result.executionAttempted, false);
    assert.equal(result.isolation.destroyAfterRun, true);
    assert.equal(result.report.sha256, sha256);
    assert.equal(posted.url, 'https://sandbox.example.test/api/inspect');
    const body = JSON.parse(posted.options.body);
    assert.equal(Buffer.from(body.data, 'base64').toString('utf8'), bytes.toString('utf8'));

    const badEvidence = new CloudEphemeralInspectionClient({
      endpoint: 'https://sandbox.example.test/api/inspect',
      fetchImpl: async () => ({
        ok: true,
        status: 200,
        json: async () => ({
          ok: true,
          report: { bytes: bytes.length, sha256: '0'.repeat(64), type: 'windows-pe' },
          isolation: {
            ephemeral: true,
            networkPolicy: 'deny-all',
            hostFallback: false,
            destroyAfterRun: true,
            execution: 'inspection-only',
          },
        }),
      }),
    });
    const rejected = await badEvidence.inspect(sample);
    assert.equal(rejected.ok, false);
    assert.equal(rejected.code, 'CLOUD_INSPECTION_INTEGRITY_FAILED');

    const unavailable = new CloudEphemeralInspectionClient({ endpoint: 'http://insecure.example.test', fetchImpl: async () => ({}) });
    assert.equal(unavailable.available(), false);
    const unavailableResult = await unavailable.inspect(sample);
    assert.equal(unavailableResult.ok, false);
    assert.equal(unavailableResult.code, 'CLOUD_INSPECTION_UNAVAILABLE');
  } finally {
    await fs.promises.rm(dir, { recursive: true, force: true });
  }

  console.log('✓ Cloud ephemeral inspection client: opt-in upload, evidence validation, fail-closed integrity and destroy-after-run contract PASS');
})().catch(error => {
  console.error(error.stack || error);
  process.exit(1);
});
