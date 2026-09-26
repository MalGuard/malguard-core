'use strict';

const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const ROOT = __dirname;
const RUN_ALL = path.join(ROOT, 'run-all.js');

const STAGES = Object.freeze({
  stage1: {
    title: 'TSH Stage 1 - Core Detection and File Intelligence',
    tests: [
      'scan-resilience.test.js',
      'script-analyzer.test.js',
      'regression-corpus.test.js',
      'quality-benchmark.test.js',
      'detector-regression.test.js',
      'malformed-fuzz.test.js',
      'pe-fuzz.test.js',
      'performance-budget.test.js',
      'web-worker.test.js',
      'scanner-core-acceptance.test.js',
      'mutation-security.test.js',
      'mutation-sensitivity.test.js',
      'self-test.test.js',
      'malwarebazaar-client.test.js',
      'threat-intel-cache.test.js',
      'threat-intel-recent-feed.test.js',
      'credential-store.test.js',
      'threat-intel-integration.test.js',
      'ai-evidence-bridge.test.js',
      'malguard-cloud-ai-provider.test.js',
      'pro-scan-pipeline.test.js',
      'fusion-engine.test.js',
      'multiengine-fusion.test.js',
    ],
  },
  stage2: {
    title: 'TSH Stage 2 - Isolation, Sandbox and Runtime Defense',
    tests: [
      'desktop-guard.test.js',
      'windows-agent.test.js',
      'protection-coordinator.test.js',
      'runtime-game-process-guard.test.js',
      'runtime-containment.test.js',
      'sandbox-backend.test.js',
      'cloud-sandbox-policy.test.js',
      'cloud-sandbox-vercel-runner.test.js',
      'cloud-sandbox-self-test-api.test.js',
      'cloud-sandbox-safe-execution.test.js',
      'cloud-sandbox-file-inspection.test.js',
      'cloud-sandbox-benign-upload-execution.test.js',
      'cloud-sandbox-benign-behavior-telemetry.test.js',
      'cloud-ephemeral-inspection-client.test.js',
      'cloud-gta-simulation.test.js',
      'cloud-gta-simulation-client.test.js',
      'malguard-microvm-backend.test.js',
      'malguard-portable-vm-backend.test.js',
      'isolation-backend-router.test.js',
      'sandbox-router-default.test.js',
      'gta-guard-sandbox-routing.test.js',
      'gta-simulation-engine.test.js',
      'gta-simulation-pipeline.test.js',
      'gta-plugin-sandbox-loader.test.js',
      'sandbox-first-run-certification.test.js',
      'virtual-windows-validation-lab.test.js',
      'embedded-validation-lab.test.js',
      'isolation-readiness.test.js',
      'sandbox-telemetry.test.js',
      'sandbox-native-containment-source.test.js',
      'windows-service-source.test.js',
      'windows-acceptance-harness.test.js',
      'ths-stage2-integration.test.js',
    ],
  },
  stage3: {
    title: 'TSH Stage 3 - Product, API, UI, Packaging and Release Integrity',
    tests: [
      'version-consistency.test.js',
      'build-validation.test.js',
      'packaging-foundation.test.js',
      'runtime-package-integrity.test.js',
      'self-heal.test.js',
      'workflow-supply-chain.test.js',
      'public-release-policy.test.js',
      'windows-installer-source.test.js',
      'secure-update.test.js',
      'update-runtime-enforcement.test.js',
      'release-trust.test.js',
      'entitlement-gate.test.js',
      'entitlement-api.test.js',
      'error-reporter.test.js',
      'runtime-error-integration.test.js',
      'final-security-audit.test.js',
      'product-readiness-gate.test.js',
      'first-launch-counter.test.js',
      'compatibility-profile.test.js',
      'install-hardware-report-api.test.js',
      'settings-store.test.js',
      'access-gate.test.js',
      'desktop-app.test.js',
      'pro-scan-api.test.js',
      'local-file-upload.test.js',
      'model-selection-ui.test.js',
      'scanner-feedback-ui.test.js',
      'ths-stage3-adversarial.test.js',
      'tsh.test.js',
    ],
  },
});

function parseCanonicalTests() {
  const source = fs.readFileSync(RUN_ALL, 'utf8');
  const match = source.match(/const\s+tests\s*=\s*\[([\s\S]*?)\];/);
  if (!match) throw new Error('TSH could not parse canonical tests list');
  return [...match[1].matchAll(/['"]([^'"]+\.test\.js)['"]/g)].map(m => m[1]);
}

function verifyPartition() {
  const canonical = parseCanonicalTests();
  const staged = Object.values(STAGES).flatMap(stage => stage.tests);

  const canonicalSet = new Set(canonical);
  const stagedSet = new Set(staged);
  const duplicates = staged.filter((test, index) => staged.indexOf(test) !== index);
  const missing = canonical.filter(test => !stagedSet.has(test));
  const extras = staged.filter(test => !canonicalSet.has(test));

  if (duplicates.length || missing.length || extras.length || staged.length !== canonical.length) {
    console.error(JSON.stringify({
      ok: false,
      canonicalCount: canonical.length,
      stagedCount: staged.length,
      duplicates: [...new Set(duplicates)],
      missing,
      extras,
    }, null, 2));
    process.exit(2);
  }

  console.log(
    '✓ TSH partition verified: ' +
    canonical.length + '/' + canonical.length +
    ' canonical test programs mapped exactly once across 3 stages'
  );
  return canonical.length;
}

function runTest(test) {
  const started = Date.now();
  console.log('→ ' + test);
  const result = spawnSync(process.execPath, [path.join(ROOT, test)], {
    stdio: 'inherit',
    timeout: 120000,
    windowsHide: true,
    env: { ...process.env, MALGUARD_TSH_MAIN: '1' },
  });
  const elapsed = Date.now() - started;

  if (result.error && result.error.code === 'ETIMEDOUT') {
    console.error('✗ ' + test + ': timed out after ' + elapsed + 'ms');
    process.exit(124);
  }
  if (result.status !== 0) {
    console.error('✗ ' + test + ': exit=' + result.status + ' signal=' + (result.signal || 'none') + ' after ' + elapsed + 'ms');
    process.exit(result.status || 1);
  }

  console.log('✓ ' + test + ': ' + elapsed + 'ms');
}

const stageName = process.argv[2];
if (!Object.prototype.hasOwnProperty.call(STAGES, stageName)) {
  console.error('Usage: node tests/tsh-main-3stage.js stage1|stage2|stage3');
  process.exit(64);
}

const total = verifyPartition();
const stage = STAGES[stageName];
const started = Date.now();

console.log('');
console.log('============================================================');
console.log(stage.title);
console.log('Scope: ' + stage.tests.length + '/' + total + ' canonical test programs');
console.log('Safety: repository fixtures only; no unknown malware execution');
console.log('============================================================');

for (const test of stage.tests) runTest(test);

console.log('');
console.log(
  '✓ ' + stage.title + ': ' +
  stage.tests.length + '/' + stage.tests.length +
  ' test programs PASS in ' + (Date.now() - started) + 'ms'
);
