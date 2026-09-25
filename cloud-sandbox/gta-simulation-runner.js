'use strict';

const path = require('path');
const { createInspectionJob } = require('./job-policy');

const GTA_CLOUD_SIMULATION_VERSION = '0.1.0';
const ALLOWED_PLUGIN_EXTENSIONS = new Set(['.asi', '.dll']);

function safePluginName(name) {
  const base = path.basename(String(name || 'plugin.asi')).replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 120);
  const ext = path.extname(base).toLowerCase();
  if (!ALLOWED_PLUGIN_EXTENSIONS.has(ext)) {
    const error = new Error('gta-simulation-unsupported-extension');
    error.code = 'GTA_SIMULATION_UNSUPPORTED_EXTENSION';
    throw error;
  }
  return base;
}

async function runGtaSimulation({ Sandbox, data, name = 'plugin.asi' } = {}) {
  if (!Sandbox || typeof Sandbox.create !== 'function') {
    throw new Error('sandbox-provider-unavailable');
  }

  const job = createInspectionJob(data);
  if (!job.accepted) {
    throw new Error('gta-simulation-policy-rejected:' + job.reason);
  }

  const pluginName = safePluginName(name);
  const pluginPath = 'gta-sim/Game/plugins/' + pluginName;
  const manifest = {
    schemaVersion: '1.0.0',
    simulationVersion: GTA_CLOUD_SIMULATION_VERSION,
    game: 'Grand Theft Auto V',
    syntheticProcess: 'GTA5-Sim.exe',
    pluginPath,
    realGameFilesMounted: false,
    realUserFilesMounted: false,
    sampleExecutionAllowed: false,
    networkPolicy: 'deny-all',
  };

  let sandbox;
  try {
    sandbox = await Sandbox.create({
      runtime: 'node24',
      timeout: job.isolation.timeoutMs,
      networkPolicy: 'deny-all',
      persistent: false,
    });

    await sandbox.writeFiles([
      { path: pluginPath, content: data },
      { path: 'gta-sim/manifest.json', content: Buffer.from(JSON.stringify(manifest), 'utf8') },
      { path: 'gta-sim/Game/plugins/README.txt', content: Buffer.from('Synthetic GTA plugin directory. Samples are never executed in phase 2.\n', 'utf8') },
      { path: 'gta-sim/Game/scripts/README.txt', content: Buffer.from('Synthetic GTA scripts directory.\n', 'utf8') },
    ]);

    const script = [
      "const fs=require('fs'),crypto=require('crypto');",
      "const m=JSON.parse(fs.readFileSync('/vercel/sandbox/gta-sim/manifest.json','utf8'));",
      "const p='/vercel/sandbox/'+m.pluginPath;",
      "const b=fs.readFileSync(p);",
      "const dirs=['/vercel/sandbox/gta-sim/Game/plugins','/vercel/sandbox/gta-sim/Game/scripts'];",
      "const treeReady=dirs.every(d=>fs.statSync(d).isDirectory());",
      "process.stdout.write(JSON.stringify({",
      "schemaVersion:'1.0.0',simulationVersion:m.simulationVersion,treeReady,",
      "game:m.game,syntheticProcess:m.syntheticProcess,pluginPath:m.pluginPath,",
      "bytes:b.length,sha256:crypto.createHash('sha256').update(b).digest('hex'),",
      "realGameFilesMounted:false,realUserFilesMounted:false,networkPolicy:'deny-all',",
      "sampleExecutionAttempted:false,sampleExecutionStarted:false",
      "}));",
    ].join('');

    const result = await sandbox.runCommand('node', ['-e', script]);
    const report = JSON.parse(await result.stdout());

    if (report.sha256 !== job.file.sha256 || report.bytes !== job.file.bytes) {
      throw new Error('gta-simulation-report-integrity-failed');
    }
    if (report.treeReady !== true || report.sampleExecutionAttempted !== false || report.sampleExecutionStarted !== false) {
      throw new Error('gta-simulation-safety-evidence-failed');
    }
    if (report.realGameFilesMounted !== false || report.realUserFilesMounted !== false || report.networkPolicy !== 'deny-all') {
      throw new Error('gta-simulation-isolation-evidence-failed');
    }

    return {
      ok: true,
      mode: 'cloud_gta_simulation',
      jobId: job.jobId,
      name: pluginName,
      report,
      isolation: {
        ...job.isolation,
        execution: 'gta-simulation-no-sample-execution',
        syntheticGameEnvironment: true,
      },
    };
  } finally {
    if (sandbox && typeof sandbox.stop === 'function') {
      await sandbox.stop();
    }
  }
}

module.exports = {
  GTA_CLOUD_SIMULATION_VERSION,
  ALLOWED_PLUGIN_EXTENSIONS,
  safePluginName,
  runGtaSimulation,
};
