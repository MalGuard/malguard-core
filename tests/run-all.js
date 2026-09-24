'use strict';
const {spawnSync}=require('child_process');
const path=require('path');
const tests=[
 'build-validation.test.js',
 'packaging-foundation.test.js',
 'runtime-package-integrity.test.js',
 'self-heal.test.js',
 'scan-resilience.test.js',
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
 'script-analyzer.test.js',
 'regression-corpus.test.js',
 'quality-benchmark.test.js',
 'detector-regression.test.js',
 'malformed-fuzz.test.js',
 'pe-fuzz.test.js',
 'performance-budget.test.js',
 'web-worker.test.js',
 'final-security-audit.test.js',
 'scanner-core-acceptance.test.js',
 'mutation-security.test.js',
 'mutation-sensitivity.test.js',
 'self-test.test.js',
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
 'cloud-sandbox-benign-upload-execution.test.js',
 'cloud-sandbox-benign-behavior-telemetry.test.js',
 'malguard-microvm-backend.test.js',
 'malguard-portable-vm-backend.test.js',
 'isolation-backend-router.test.js',
 'sandbox-router-default.test.js',
 'gta-guard-sandbox-routing.test.js',
 'sandbox-first-run-certification.test.js',
 'virtual-windows-validation-lab.test.js',
 'embedded-validation-lab.test.js',
 'isolation-readiness.test.js',
 'product-readiness-gate.test.js',
 'sandbox-telemetry.test.js',
 'sandbox-native-containment-source.test.js',
 'windows-service-source.test.js',
 'windows-acceptance-harness.test.js',
 'first-launch-counter.test.js',
 'compatibility-profile.test.js',
 'install-hardware-report-api.test.js',
 'settings-store.test.js',
 'access-gate.test.js',
 'malwarebazaar-client.test.js',
 'threat-intel-cache.test.js',
 'threat-intel-recent-feed.test.js',
 'credential-store.test.js',
 'threat-intel-integration.test.js',
 'desktop-app.test.js',
 'pro-scan-pipeline.test.js',
 'pro-scan-api.test.js',
 'local-file-upload.test.js',
 'model-selection-ui.test.js',
];
for(const test of tests){
 const started=Date.now();
 console.log(`→ ${test}`);
 const r=spawnSync(process.execPath,[path.join(__dirname,test)],{
  stdio:'inherit',
  timeout:120000,
  windowsHide:true,
 });
 const elapsed=Date.now()-started;
 if(r.error && r.error.code==='ETIMEDOUT'){
  console.error(`✗ ${test}: timed out after ${elapsed}ms`);
  process.exit(124);
 }
 if(r.status!==0){
  console.error(`✗ ${test}: exit=${r.status} signal=${r.signal||'none'} after ${elapsed}ms`);
  process.exit(r.status||1);
 }
 console.log(`✓ ${test}: ${elapsed}ms`);
}
console.log(`✓ Full Engineering Hardening suite: ${tests.length}/${tests.length} test programs passed`);
