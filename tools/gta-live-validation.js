'use strict';

const fs = require('fs');
const path = require('path');
const { SandboxController } = require('../desktop-app/sandbox/sandbox-controller.js');

async function main() {
  const samplePath = process.argv[2] ? path.resolve(process.argv[2]) : '';
  const reportPath = process.argv[3] ? path.resolve(process.argv[3]) : '';
  if (!samplePath || !reportPath) {
    throw new Error('usage: node tools/gta-live-validation.js <benign-plugin.asi> <report.json>');
  }

  const controller = new SandboxController();
  const result = await controller.analyzeUntrustedSample(samplePath);
  const game = result && result.telemetry && result.telemetry.gameContext;
  const report = {
    generatedAt: new Date().toISOString(),
    sample: path.basename(samplePath),
    ok: result && result.ok === true,
    verdict: result && result.verdict || 'inconclusive',
    code: result && result.code || null,
    sandboxLaunched: result && result.sandboxLaunched === true,
    sampleExecutionStarted: result && result.sampleExecutionStarted === true,
    realGame: !!(game && game.realGame === true),
    hostGameReadOnly: !!(game && game.hostGameReadOnly === true),
    stagingMode: game && game.stagingMode || null,
    pluginMode: !!(game && game.pluginMode === true),
    pluginLoadProven: !!(game && game.pluginLoadProven === true),
    processName: game && game.processName || null,
    execution: result && result.telemetry && result.telemetry.execution || null,
    blockers: result && result.certification && Array.isArray(result.certification.blockers)
      ? result.certification.blockers
      : [],
  };

  await fs.promises.mkdir(path.dirname(reportPath), { recursive: true });
  await fs.promises.writeFile(reportPath, JSON.stringify(report, null, 2));
  process.stdout.write(JSON.stringify(report, null, 2) + '\n');

  const passed = report.ok === true &&
    report.sandboxLaunched === true &&
    report.sampleExecutionStarted === true &&
    report.realGame === true &&
    report.hostGameReadOnly === true &&
    report.stagingMode === 'sandbox-local-full-copy' &&
    report.pluginMode === true &&
    report.pluginLoadProven === true;

  if (!passed) process.exitCode = 2;
}

main().catch(async error => {
  console.error(error && error.stack || error);
  process.exitCode = 1;
});
