'use strict';

const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const ROOT = __dirname;
const RUN_ALL = path.join(ROOT, 'run-all.js');

const STAGES = Object.freeze({
  stage1: { title:'TSH 1/10 - Source, Version and Release Identity', tests:[
    'version-consistency.test.js','build-validation.test.js','workflow-supply-chain.test.js',
    'public-release-policy.test.js','windows-installer-source.test.js','release-trust.test.js'
  ]},
  stage2: { title:'TSH 2/10 - Packaging, Integrity and Update Hardening', tests:[
    'packaging-foundation.test.js','runtime-package-integrity.test.js','self-heal.test.js',
    'secure-update.test.js','update-runtime-enforcement.test.js'
  ]},
  stage3: { title:'TSH 3/10 - Core Static Detection and Parser Abuse', tests:[
    'scan-resilience.test.js','regression-corpus.test.js','quality-benchmark.test.js',
    'detector-regression.test.js','malformed-fuzz.test.js','pe-fuzz.test.js',
    'performance-budget.test.js','web-worker.test.js','final-security-audit.test.js',
    'scanner-core-acceptance.test.js','mutation-security.test.js','mutation-sensitivity.test.js'
  ]},
  stage4: { title:'TSH 4/10 - Script, Input, Local API and Error Foundations', tests:[
    'script-analyzer.test.js','self-test.test.js','local-file-upload.test.js','desktop-app.test.js',
    'settings-store.test.js','access-gate.test.js','error-reporter.test.js','runtime-error-integration.test.js'
  ]},
  stage5: { title:'TSH 5/10 - Independent Engines and Fusion Arbitration', tests:[
    'fusion-engine.test.js','multiengine-fusion.test.js','ths-stage2-integration.test.js',
    'ths-stage3-adversarial.test.js','tsh.test.js'
  ]},
  stage6: { title:'TSH 6/10 - AI, Threat Intelligence and Credential Privacy', tests:[
    'ai-evidence-bridge.test.js','malguard-cloud-ai-provider.test.js','malwarebazaar-client.test.js',
    'threat-intel-cache.test.js','threat-intel-recent-feed.test.js','credential-store.test.js',
    'threat-intel-integration.test.js'
  ]},
  stage7: { title:'TSH 7/10 - Cloud Sandbox and GTA Simulation', tests:[
    'sandbox-backend.test.js','cloud-sandbox-policy.test.js','cloud-sandbox-vercel-runner.test.js',
    'cloud-sandbox-self-test-api.test.js','cloud-sandbox-safe-execution.test.js',
    'cloud-sandbox-file-inspection.test.js','cloud-sandbox-benign-upload-execution.test.js',
    'cloud-sandbox-benign-behavior-telemetry.test.js','cloud-ephemeral-inspection-client.test.js',
    'cloud-gta-simulation.test.js','cloud-gta-simulation-client.test.js',
    'gta-simulation-engine.test.js','gta-simulation-pipeline.test.js'
  ]},
  stage8: { title:'TSH 8/10 - Isolation Backends and Sandbox Routing', tests:[
    'malguard-microvm-backend.test.js','malguard-portable-vm-backend.test.js',
    'isolation-backend-router.test.js','sandbox-router-default.test.js','gta-guard-sandbox-routing.test.js',
    'gta-plugin-sandbox-loader.test.js','sandbox-first-run-certification.test.js',
    'virtual-windows-validation-lab.test.js','embedded-validation-lab.test.js',
    'isolation-readiness.test.js','sandbox-telemetry.test.js'
  ]},
  stage9: { title:'TSH 9/10 - Runtime, Native Windows and Host Defense', tests:[
    'desktop-guard.test.js','windows-agent.test.js','protection-coordinator.test.js',
    'runtime-game-process-guard.test.js','runtime-containment.test.js',
    'sandbox-native-containment-source.test.js','windows-service-source.test.js',
    'windows-acceptance-harness.test.js','first-launch-counter.test.js',
    'compatibility-profile.test.js','install-hardware-report-api.test.js'
  ]},
  stage10:{ title:'TSH 10/10 - Product Models, Entitlements, UI and Final Readiness', tests:[
    'entitlement-gate.test.js','entitlement-api.test.js','product-readiness-gate.test.js',
    'pro-scan-pipeline.test.js','pro-scan-api.test.js','model-selection-ui.test.js',
    'scanner-feedback-ui.test.js'
  ]},
});

function canonicalTests(){
  const src=fs.readFileSync(RUN_ALL,'utf8');
  const m=src.match(/const\s+tests\s*=\s*\[([\s\S]*?)\];/);
  if(!m) throw new Error('TSH could not parse canonical tests list');
  return [...m[1].matchAll(/['"]([^'"]+\.test\.js)['"]/g)].map(x=>x[1]);
}

function verifyPartition(){
  const canonical=canonicalTests();
  const staged=Object.values(STAGES).flatMap(s=>s.tests);
  const stagedSet=new Set(staged);
  const canonicalSet=new Set(canonical);
  const duplicates=staged.filter((t,i)=>staged.indexOf(t)!==i);
  const missing=canonical.filter(t=>!stagedSet.has(t));
  const extras=staged.filter(t=>!canonicalSet.has(t));
  if(duplicates.length||missing.length||extras.length||staged.length!==canonical.length){
    console.error(JSON.stringify({ok:false,canonicalCount:canonical.length,stagedCount:staged.length,duplicates:[...new Set(duplicates)],missing,extras},null,2));
    process.exit(2);
  }
  console.log('✓ TSH 10-stage partition verified: '+canonical.length+'/'+canonical.length+' canonical tests mapped exactly once');
  return canonical.length;
}

function runTest(test){
  const started=Date.now();
  console.log('→ '+test);
  const result=spawnSync(process.execPath,[path.join(ROOT,test)],{
    stdio:'inherit',timeout:120000,windowsHide:true,
    env:{...process.env,MALGUARD_TSH_MAIN:'1',MALGUARD_TSH_10_STAGE:'1'}
  });
  const elapsed=Date.now()-started;
  if(result.error&&result.error.code==='ETIMEDOUT'){console.error('✗ '+test+': timeout '+elapsed+'ms');process.exit(124);}
  if(result.status!==0){console.error('✗ '+test+': exit='+result.status+' signal='+(result.signal||'none')+' after '+elapsed+'ms');process.exit(result.status||1);}
  console.log('✓ '+test+': '+elapsed+'ms');
}

const stageName=process.argv[2];
if(!Object.prototype.hasOwnProperty.call(STAGES,stageName)){
  console.error('Usage: node tests/tsh-main-10stage.js stage1..stage10');
  process.exit(64);
}
const total=verifyPartition();
const stage=STAGES[stageName];
console.log('\n============================================================');
console.log(stage.title);
console.log('Scope: '+stage.tests.length+'/'+total+' canonical test programs');
console.log('Safety: repository fixtures only; no unknown malware execution');
console.log('============================================================');
for(const test of stage.tests) runTest(test);
console.log('✓ '+stage.title+': '+stage.tests.length+'/'+stage.tests.length+' PASS');
