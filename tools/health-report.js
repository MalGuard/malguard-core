'use strict';

const { SafeSelfHeal } = require('../desktop-app/health/self-heal.js');
const { ScannerBridge } = require('../desktop-app/scanner-bridge.js');
const { SandboxController } = require('../desktop-app/sandbox/sandbox-controller.js');
const { verifyRuntimePackageIntegrity } = require('../desktop-app/integrity/runtime-integrity.js');
const path = require('path');

async function main() {
  const root = path.resolve(__dirname, '..');
  const selfHeal = new SafeSelfHeal().repairSync();
  const scanner = new ScannerBridge();
  const scanProbe = await scanner.scanBuffer('malguard-health-probe.lua', Buffer.from('local x = 2 + 2\nprint(x)\n'), 'free');
  const scannerOperational = !!(scanProbe && scanProbe.resultSchemaVersion === '1.0.0' && scanProbe.hardeningError !== 'desktop_bridge_error');
  const sandbox = new SandboxController();
  const sandboxSelfTest = await sandbox.selfTest();
  const runtimeIntegrity = verifyRuntimePackageIntegrity(root, { requireSealed: false });

  const report = {
    schemaVersion: '1.0.0',
    generatedAt: new Date().toISOString(),
    coreReady: selfHeal.ok === true && scannerOperational && runtimeIntegrity.ok === true,
    selfHeal,
    scanner: {
      ok: scannerOperational,
      verdict: scanProbe && scanProbe.finalVerdict,
      hardeningError: scanProbe && scanProbe.hardeningError || null,
      note: 'The health probe validates that the scanner executes and returns a fail-closed contract. A synthetic health fixture is not required to receive a SAFE verdict.',
    },
    sandbox: {
      ready: sandboxSelfTest.releaseReady === true,
      executionCertified: sandboxSelfTest.executionCertified === true,
      blockers: sandboxSelfTest.blockers || [],
      result: sandboxSelfTest,
    },
    runtimeIntegrity,
    interpretation: 'coreReady covers local scanning and MalGuard-owned runtime state. Sandbox readiness is reported separately because Windows Sandbox is an OS capability and is never faked or bypassed.',
  };
  process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  process.exitCode = report.coreReady ? 0 : 1;
}

if (require.main === module) {
  main().catch(error => {
    console.error(error && error.stack ? error.stack : error);
    process.exit(1);
  });
}

module.exports = { main };
