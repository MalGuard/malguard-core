'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const {
  GtaSimulationEngine,
  GTA_SIMULATION_VERSION,
  SYNTHETIC_ENVIRONMENT,
} = require('../desktop-app/gta-simulation/simulation-engine.js');

(() => {
  const engine = new GtaSimulationEngine();
  const caps = engine.capabilities();

  assert.equal(caps.ok, true);
  assert.equal(caps.version, GTA_SIMULATION_VERSION);
  assert.equal(caps.untrustedCodeExecution, false);
  assert.equal(caps.environment.networkPolicy, 'deny-all');
  assert.equal(caps.environment.realGameFilesMounted, false);
  assert.equal(caps.environment.realUserFilesMounted, false);
  assert.equal(caps.environment.directSampleExecution, false);
  assert.equal(caps.verdictPolicy.canPromoteSafe, false);

  const standard = engine.analyze({
    filePath: 'C:\\Mods\\menu.asi',
    model: 'standard',
    localResult: {
      finalVerdict: 'safe',
      contentSha256: 'a'.repeat(64),
      detectorResult: { modType: 'plugin', route: 'ENGINE', confidence: 'high', suspiciousPackaging: false },
      threatIntel: { status: 'hash_not_found' },
    },
  });
  assert.equal(standard.ok, true);
  assert.equal(standard.depth, 'profile-only');
  assert.equal(standard.sampleProfile.gtaPluginCandidate, true);
  assert.equal(standard.sampleProfile.directExecutionAttempted, false);
  assert.equal(standard.verdictPolicy.canPromoteSafe, false);
  assert.equal(standard.remediationPlan.available, false);

  const plus = engine.analyze({
    filePath: 'C:\\Mods\\menu.dll',
    model: 'plus',
    localResult: {
      finalVerdict: 'suspicious',
      detectorResult: { modType: 'plugin', route: 'ENGINE', confidence: 'medium', suspiciousPackaging: true },
      threatIntel: { status: 'unavailable' },
    },
  });
  assert.equal(plus.depth, 'synthetic-runtime-model');
  assert.equal(plus.remediationPlan.available, true);
  assert.equal(plus.remediationPlan.autoApply, false);
  assert.equal(plus.remediationPlan.hostMutationAllowed, false);
  assert.equal(plus.remediationPlan.userApprovalRequired, true);
  assert(plus.remediationPlan.actions.includes('keep_blocked'));
  assert(plus.evidence.signals.includes('suspicious_packaging'));

  const pro = engine.analyze({
    filePath: 'C:\\Mods\\menu.asi',
    model: 'pro',
    localResult: {
      finalVerdict: 'malicious',
      detectorResult: { modType: 'plugin', route: 'ENGINE', confidence: 'high', suspiciousPackaging: false },
      threatIntel: { status: 'known_malicious' },
    },
  });
  assert.equal(pro.depth, 'synthetic-runtime-model-plus-remediation');
  assert(pro.remediationPlan.actions.includes('quarantine_sample'));
  assert.equal(pro.remediationPlan.hostMutationAllowed, false);
  assert.equal(pro.verdictPolicy.advisoryOnly, true);

  assert.equal(SYNTHETIC_ENVIRONMENT.userData, 'synthetic-only');

  const source = fs.readFileSync(path.join(__dirname, '..', 'desktop-app', 'gta-simulation', 'simulation-engine.js'), 'utf8');
  assert(!/require\(['"]child_process['"]\)/.test(source), 'simulation engine must not spawn processes');
  assert(!/require\(['"]fs['"]\)/.test(source), 'simulation engine must not read host files');
  assert(!/\beval\s*\(/.test(source), 'simulation engine must not evaluate sample code');
  assert(!/new\s+Function\s*\(/.test(source), 'simulation engine must not compile sample code');

  console.log('✓ GTA Simulation Engine phase 1: synthetic-only environment, no sample execution, no host mutation and fail-closed verdict policy PASS');
})();
