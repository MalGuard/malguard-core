'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { SandboxController } = require('../desktop-app/sandbox/sandbox-controller.js');

function executedResult() {
  return {
    ok: true,
    verdict: 'inconclusive',
    releaseGrade: true,
    telemetry: {
      execution: {
        attempted: true,
        started: true,
        timedOut: false,
        exitCode: 0,
        error: null,
      },
    },
  };
}

(async () => {
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'malguard-gta-plugin-route-'));
  try {
    const plugin = path.join(dir, 'menu.asi');
    await fs.promises.writeFile(plugin, Buffer.from('MZ synthetic GTA plugin routing fixture'));

    let windowsAnalyzeCalls = 0;
    let genericAnalyzeCalls = 0;
    const windowsBackend = {
      capabilities: async () => ({ backend: 'windows-sandbox', available: true, releaseGrade: true }),
      analyze: async () => { windowsAnalyzeCalls++; return executedResult(); },
    };
    const router = {
      windowsSandboxBackend: windowsBackend,
      capabilities: async () => ({
        backend: 'malguard-isolation-router',
        selectedBackend: 'windows-sandbox',
        available: true,
        releaseGrade: true,
      }),
      analyze: async () => { genericAnalyzeCalls++; return executedResult(); },
    };

    const certified = new SandboxController({ isolationBackend: router });
    certified._certification = {
      state: 'certified',
      ok: true,
      sandboxVersion: '0.6.1',
      certifiedAt: new Date().toISOString(),
      selectedBackend: 'windows-sandbox',
      blockers: [],
    };
    certified.ensureRuntimeCertified = async () => certified._certification;

    const preflight = await certified.preflightSample(plugin);
    assert.equal(preflight.ok, true);
    assert.equal(preflight.extension, '.asi');

    const executed = await certified.analyzeUntrustedSample(plugin);
    assert.equal(executed.ok, true);
    assert.equal(windowsAnalyzeCalls, 1, 'GTA plugin must go directly to the certified Windows Sandbox backend');
    assert.equal(genericAnalyzeCalls, 0, 'GTA plugin must never execute through the generic backend router');
    assert.equal(executed.gtaPluginExecution.backend, 'windows-sandbox');
    assert.equal(executed.gtaPluginExecution.syntheticGameEnvironment, true);
    assert.equal(executed.gtaPluginExecution.hostFallback, false);
    assert.equal(executed.sampleExecutionStarted, true);
    assert.equal(executed.sandboxLaunched, true);

    windowsAnalyzeCalls = 0;
    genericAnalyzeCalls = 0;
    const fallbackSelected = new SandboxController({ isolationBackend: router });
    fallbackSelected._certification = {
      state: 'certified',
      ok: true,
      sandboxVersion: '0.6.1',
      certifiedAt: new Date().toISOString(),
      selectedBackend: 'microvm',
      blockers: [],
    };
    fallbackSelected.ensureRuntimeCertified = async () => fallbackSelected._certification;

    const blocked = await fallbackSelected.analyzeUntrustedSample(plugin);
    assert.equal(blocked.ok, false);
    assert.equal(blocked.code, 'GTA_PLUGIN_WINDOWS_SANDBOX_REQUIRED');
    assert.equal(blocked.sandboxLaunched, false);
    assert.equal(blocked.sampleExecutionStarted, false);
    assert.equal(windowsAnalyzeCalls, 0);
    assert.equal(genericAnalyzeCalls, 0);

    console.log('✓ GTA plugin routing: ASI/DLL behavioral loading is Windows-Sandbox-only and generic backend fallback cannot execute plugins');
  } finally {
    await fs.promises.rm(dir, { recursive: true, force: true });
  }
})().catch(error => {
  console.error(error.stack || error);
  process.exit(1);
});
