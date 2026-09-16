'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { WindowsSandboxBackend } = require('../desktop-app/sandbox/windows-sandbox-backend.js');
const { SandboxController } = require('../desktop-app/sandbox/sandbox-controller.js');

function parseArgs(argv) {
  const out = { probe: null, report: null };
  for (let i = 2; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--probe') out.probe = argv[++i] || null;
    else if (arg === '--report') out.report = argv[++i] || null;
    else throw new Error(`unknown argument: ${arg}`);
  }
  return out;
}

async function writeJsonAtomic(target, value) {
  const resolved = path.resolve(target);
  await fs.promises.mkdir(path.dirname(resolved), { recursive: true });
  const temp = `${resolved}.${process.pid}.${Date.now()}.tmp`;
  await fs.promises.writeFile(temp, JSON.stringify(value, null, 2), { encoding: 'utf8', flag: 'wx' });
  await fs.promises.rename(temp, resolved);
}

(async () => {
  const args = parseArgs(process.argv);
  if (!args.probe) throw new Error('--probe is required');

  const backend = new WindowsSandboxBackend({
    containmentProbePath: path.resolve(args.probe),
    preserveSessions: false,
  });
  const controller = new SandboxController({ windowsBackend: backend });

  const startedAt = new Date().toISOString();
  const selfTest = await controller.selfTest();
  const report = {
    schemaVersion: '1.1.0',
    kind: 'malguard-windows-sandbox-acceptance',
    startedAt,
    completedAt: new Date().toISOString(),
    host: {
      platform: process.platform,
      arch: process.arch,
      release: os.release(),
      node: process.version,
    },
    safety: {
      untrustedSamplesExecuted: false,
      arbitraryExecutableAccepted: false,
      harmlessSandboxExecutionProbe: true,
      harmlessExecutionProbePassed: selfTest.executionCertified === true,
      note: 'Synthetic containment/isolation checks plus one built-in harmless .cmd execution probe inside Windows Sandbox only.',
    },
    selfTest,
    pass: selfTest.releaseReady === true && selfTest.executionCertified === true,
  };

  if (args.report) await writeJsonAtomic(args.report, report);
  process.stdout.write(`${JSON.stringify(report)}\n`);
  process.exit(report.pass ? 0 : 2);
})().catch((error) => {
  const report = {
    schemaVersion: '1.1.0',
    kind: 'malguard-windows-sandbox-acceptance',
    pass: false,
    fatalError: error && error.message ? error.message : String(error),
  };
  process.stdout.write(`${JSON.stringify(report)}\n`);
  process.exit(3);
});
