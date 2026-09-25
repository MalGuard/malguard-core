'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const {
  CloudGtaSimulationClient,
  DEFAULT_GTA_SIMULATION_ENDPOINT,
} = require('../desktop-app/gta-simulation/cloud-gta-simulation-client.js');

(async () => {
  assert.match(DEFAULT_GTA_SIMULATION_ENDPOINT, /^https:\/\//);

  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'malguard-gta-cloud-'));
  try {
    const file = path.join(dir, 'menu.asi');
    const bytes = Buffer.from('MZ harmless GTA simulation fixture');
    const sha256 = crypto.createHash('sha256').update(bytes).digest('hex');
    await fs.promises.writeFile(file, bytes);

    let posted = null;
    const client = new CloudGtaSimulationClient({
      endpoint: 'https://sandbox.example.test/api/cloud-gta-simulation',
      fetchImpl: async (url, options) => {
        posted = { url, body: JSON.parse(options.body) };
        return {
          ok: true,
          status: 200,
          json: async () => ({
            ok: true,
            mode: 'cloud_gta_simulation',
            report: {
              treeReady: true,
              bytes: bytes.length,
              sha256,
              realGameFilesMounted: false,
              realUserFilesMounted: false,
              networkPolicy: 'deny-all',
              sampleExecutionAttempted: false,
              sampleExecutionStarted: false,
            },
            isolation: {
              ephemeral: true,
              networkPolicy: 'deny-all',
              hostFallback: false,
              destroyAfterRun: true,
              syntheticGameEnvironment: true,
              execution: 'gta-simulation-no-sample-execution',
            },
          }),
        };
      },
    });

    assert.equal(client.available(), true);
    assert.equal(client.supports(file), true);
    assert.equal(client.supports(path.join(dir, 'menu.exe')), false);

    const result = await client.simulate(file);
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.equal(result.mode, 'cloud_gta_simulation');
    assert.equal(result.sampleExecutionAttempted, false);
    assert.equal(result.sampleExecutionStarted, false);
    assert.equal(result.report.treeReady, true);
    assert.equal(result.isolation.destroyAfterRun, true);
    assert.equal(posted.url, 'https://sandbox.example.test/api/cloud-gta-simulation');
    assert.equal(posted.body.name, 'menu.asi');
    assert.equal(Buffer.from(posted.body.data, 'base64').toString('utf8'), bytes.toString('utf8'));

    const unsupported = await client.simulate(path.join(dir, 'menu.exe'));
    assert.equal(unsupported.ok, false);
    assert.equal(unsupported.code, 'GTA_CLOUD_SIMULATION_UNSUPPORTED_EXTENSION');

    const bad = new CloudGtaSimulationClient({
      endpoint: 'https://sandbox.example.test/api/cloud-gta-simulation',
      fetchImpl: async () => ({
        ok: true,
        status: 200,
        json: async () => ({
          ok: true,
          mode: 'cloud_gta_simulation',
          report: {
            treeReady: true,
            bytes: bytes.length,
            sha256,
            realGameFilesMounted: false,
            realUserFilesMounted: false,
            networkPolicy: 'deny-all',
            sampleExecutionAttempted: true,
            sampleExecutionStarted: true,
          },
          isolation: {
            ephemeral: true,
            networkPolicy: 'deny-all',
            hostFallback: false,
            destroyAfterRun: true,
            syntheticGameEnvironment: true,
          },
        }),
      }),
    });
    const rejected = await bad.simulate(file);
    assert.equal(rejected.ok, false);
    assert.equal(rejected.code, 'GTA_CLOUD_SIMULATION_SAFETY_EVIDENCE_FAILED');
  } finally {
    await fs.promises.rm(dir, { recursive: true, force: true });
  }

  console.log('✓ Cloud GTA simulation client: extension gate, upload integrity and no-execution evidence validation PASS');
})().catch(error => {
  console.error(error.stack || error);
  process.exit(1);
});
