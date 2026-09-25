'use strict';

const assert = require('assert');
const crypto = require('crypto');
const {
  runGtaSimulation,
  safePluginName,
  GTA_CLOUD_SIMULATION_VERSION,
} = require('../cloud-sandbox/gta-simulation-runner.js');

(async () => {
  assert.equal(safePluginName('menu.asi'), 'menu.asi');
  assert.equal(safePluginName('unsafe name.dll'), 'unsafe_name.dll');
  assert.throws(() => safePluginName('not-a-plugin.exe'), /unsupported-extension/);

  let stopped = false;
  let createOptions = null;
  const files = new Map();

  const Sandbox = {
    async create(options) {
      createOptions = options;
      return {
        async writeFiles(entries) {
          for (const entry of entries) files.set(entry.path, Buffer.from(entry.content));
        },
        async runCommand(command, args) {
          assert.equal(command, 'node');
          assert.equal(args[0], '-e');
          const manifest = JSON.parse(files.get('gta-sim/manifest.json').toString('utf8'));
          const bytes = files.get(manifest.pluginPath);
          const report = {
            schemaVersion: '1.0.0',
            simulationVersion: manifest.simulationVersion,
            treeReady: files.has('gta-sim/Game/plugins/README.txt') && files.has('gta-sim/Game/scripts/README.txt'),
            game: manifest.game,
            syntheticProcess: manifest.syntheticProcess,
            pluginPath: manifest.pluginPath,
            bytes: bytes.length,
            sha256: crypto.createHash('sha256').update(bytes).digest('hex'),
            realGameFilesMounted: false,
            realUserFilesMounted: false,
            networkPolicy: 'deny-all',
            sampleExecutionAttempted: false,
            sampleExecutionStarted: false,
          };
          return { stdout: async () => JSON.stringify(report) };
        },
        async stop() { stopped = true; },
      };
    },
  };

  const data = Buffer.from('MZ benign synthetic plugin fixture');
  const result = await runGtaSimulation({ Sandbox, data, name: 'menu.asi' });

  assert.equal(result.ok, true);
  assert.equal(result.mode, 'cloud_gta_simulation');
  assert.equal(result.report.simulationVersion, GTA_CLOUD_SIMULATION_VERSION);
  assert.equal(result.report.treeReady, true);
  assert.equal(result.report.sampleExecutionAttempted, false);
  assert.equal(result.report.sampleExecutionStarted, false);
  assert.equal(result.report.realGameFilesMounted, false);
  assert.equal(result.report.realUserFilesMounted, false);
  assert.equal(result.isolation.ephemeral, true);
  assert.equal(result.isolation.networkPolicy, 'deny-all');
  assert.equal(result.isolation.hostFallback, false);
  assert.equal(result.isolation.destroyAfterRun, true);
  assert.equal(result.isolation.syntheticGameEnvironment, true);
  assert.equal(result.isolation.execution, 'gta-simulation-no-sample-execution');
  assert.equal(createOptions.networkPolicy, 'deny-all');
  assert.equal(createOptions.persistent, false);
  assert.equal(stopped, true);

  console.log('✓ Cloud GTA simulation: synthetic filesystem, deny-all networking, no sample execution and destroy-after-run PASS');
})().catch(error => {
  console.error(error.stack || error);
  process.exit(1);
});
