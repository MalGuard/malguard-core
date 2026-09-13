'use strict';
const {spawnSync}=require('child_process');
const path=require('path');
const tests=[
 'build-validation.test.js',
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
 'runtime-containment.test.js',
 'sandbox-backend.test.js',
 'sandbox-telemetry.test.js',
 'sandbox-native-containment-source.test.js',
 'windows-service-source.test.js',
 'windows-acceptance-harness.test.js',
 'settings-store.test.js',
 'access-gate.test.js',
 'malwarebazaar-client.test.js',
 'threat-intel-cache.test.js',
 'credential-store.test.js',
 'threat-intel-integration.test.js',
 'desktop-app.test.js',
 'pro-scan-pipeline.test.js',
 'pro-scan-api.test.js',
 'model-selection-ui.test.js',
];
for(const test of tests){
 const r=spawnSync(process.execPath,[path.join(__dirname,test)],{stdio:'inherit'});
 if(r.status!==0) process.exit(r.status||1);
}
console.log(`✓ Full Engineering Hardening suite: ${tests.length}/${tests.length} test programs passed`);
