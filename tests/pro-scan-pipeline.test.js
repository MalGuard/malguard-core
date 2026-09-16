'use strict';
const assert = require('assert');
const {
  ModelScanPipelineManager,
  ProScanPipelineManager,
  normalizeModel,
  shouldSandbox,
  sandboxExecutionProven,
  mergeSandboxVerdict,
  directSandboxVerdict,
} = require('../desktop-app/pro-scan-pipeline.js');

function waitFor(manager, id, timeoutMs = 2000) {
  const started = Date.now();
  return new Promise((resolve, reject) => {
    const tick = () => {
      const s = manager.snapshot(id);
      if (!s) return reject(new Error('session disappeared'));
      if (s.state === 'completed' || s.state === 'failed') return resolve(s);
      if (Date.now() - started > timeoutMs) return reject(new Error('pipeline timeout'));
      setTimeout(tick, 10);
    };
    tick();
  });
}

function sandboxMock(overrides = {}) {
  return {
    preflightSample: async () => ({ ok: true, sha256: 'f'.repeat(64), size: 12, extension: '.js', revalidated: true }),
    analyzeUntrustedSample: async () => ({
      ok: false,
      verdict: 'inconclusive',
      code: 'HARDENED_SANDBOX_ACCEPTANCE_PENDING',
      sandboxLaunched: false,
      sampleExecutionStarted: false,
    }),
    ...overrides,
  };
}

function executedResult(verdict, extra = {}) {
  return {
    ok: true,
    verdict,
    sandboxLaunched: true,
    sampleExecutionStarted: true,
    ...extra,
  };
}

(async()=>{
 assert.equal(normalizeModel('standard'),'standard');
 assert.equal(normalizeModel('plus'),'plus');
 assert.equal(normalizeModel('pro'),'pro');
 assert.equal(normalizeModel('legacy'),null);
 assert.equal(shouldSandbox('safe'), false);
 assert.equal(shouldSandbox('malicious'), false);
 assert.equal(shouldSandbox('suspicious'), true);
 assert.equal(shouldSandbox('inconclusive'), true);
 assert.equal(sandboxExecutionProven({ok:true,sandboxLaunched:true,sampleExecutionStarted:true}),true);
 assert.equal(sandboxExecutionProven({ok:true,sandboxLaunched:false,sampleExecutionStarted:true}),false);
 assert.equal(mergeSandboxVerdict('suspicious',executedResult('safe')),'suspicious');
 assert.equal(mergeSandboxVerdict('inconclusive',executedResult('malicious')),'malicious');
 assert.equal(mergeSandboxVerdict('inconclusive',{ok:true,verdict:'malicious'}),'inconclusive','unproven Sandbox output must not affect verdict');
 assert.equal(directSandboxVerdict({verdict:'safe'}),'inconclusive');
 assert.equal(directSandboxVerdict(executedResult('safe',{releaseGrade:true})),'safe');
 assert.equal(directSandboxVerdict({ok:true,verdict:'malicious',sandboxLaunched:false,sampleExecutionStarted:false}),'inconclusive');

 // Standard maps to the lightweight/free core and never uses Sandbox.
 let standardMode = null;
 let standardSandboxCalls = 0;
 const standardManager = new ModelScanPipelineManager({
   scanner:{scanPath:async(_p,mode)=>{standardMode=mode;return {finalVerdict:'safe',contentSha256:'a'.repeat(64)}}},
   sandbox:sandboxMock({analyzeUntrustedSample:async()=>{standardSandboxCalls++;return executedResult('safe')}}),
 });
 const standard=await waitFor(standardManager,standardManager.start('/tmp/safe.lua','standard').id);
 assert.equal(standard.finalResult.model,'standard');
 assert.equal(standard.finalResult.verdict,'safe');
 assert.equal(standard.finalResult.sandboxRequested,false);
 assert.equal(standardMode,'free');
 assert.equal(standardSandboxCalls,0);

 // Plus is the old deep Pro flow: deep scan first, Sandbox only when needed.
 let plusMode = null;
 let plusSandboxCalls = 0;
 const plusSafeManager = new ModelScanPipelineManager({
   scanner:{scanPath:async(_p,mode)=>{plusMode=mode;return {finalVerdict:'safe',contentSha256:'b'.repeat(64),scriptAnalysis:{finalVerdict:'safe'},threatIntel:{status:'hash_not_found',source:'live'}}}},
   sandbox:sandboxMock({analyzeUntrustedSample:async()=>{plusSandboxCalls++;return executedResult('safe')}}),
 });
 const plusSafe=await waitFor(plusSafeManager,plusSafeManager.start('/tmp/safe.lua','plus').id);
 assert.equal(plusSafe.finalResult.model,'plus');
 assert.equal(plusSafe.finalResult.verdict,'safe');
 assert.equal(plusSafe.finalResult.sandboxRequested,false);
 assert.equal(plusMode,'pro');
 assert.equal(plusSandboxCalls,0);
 assert(plusSafe.events.some(e=>e.phase==='script_analysis'));

 const plusSuspiciousManager = new ModelScanPipelineManager({
   scanner:{scanPath:async()=>({finalVerdict:'suspicious',contentSha256:'c'.repeat(64),threatIntel:{status:'unavailable'}})},
   sandbox:sandboxMock(),
 });
 const plusSus=await waitFor(plusSuspiciousManager,plusSuspiciousManager.start('/tmp/suspicious.cs','plus').id);
 assert.equal(plusSus.finalResult.model,'plus');
 assert.equal(plusSus.finalResult.verdict,'suspicious');
 assert.equal(plusSus.finalResult.sandboxRequested,true);
 assert.equal(plusSus.finalResult.sandboxStarted,false);
 assert.equal(plusSus.finalResult.sampleExecutionStarted,false);
 assert.equal(plusSus.finalResult.sandboxCompleted,false);
 assert(plusSus.events.some(e=>e.phase==='sandbox_decision'&&e.status==='warning'));

 // New Pro goes directly to Sandbox. The normal scanner must not run at all.
 let proScannerCalls = 0;
 let proSandboxCalls = 0;
 const proManager = new ModelScanPipelineManager({
   scanner:{scanPath:async()=>{proScannerCalls++;throw new Error('Pro must not run normal scanner')}},
   sandbox:sandboxMock({analyzeUntrustedSample:async()=>{proSandboxCalls++;return {ok:false,verdict:'inconclusive',code:'HARDENED_SANDBOX_ACCEPTANCE_PENDING',sandboxLaunched:false,sampleExecutionStarted:false}}}),
 });
 const pro=await waitFor(proManager,proManager.start('/tmp/sample.js','pro').id);
 assert.equal(pro.finalResult.model,'pro');
 assert.equal(pro.finalResult.verdict,'inconclusive');
 assert.equal(pro.finalResult.sandboxRequested,true);
 assert.equal(pro.finalResult.sandboxStarted,false,'requesting Sandbox is not evidence that Windows Sandbox actually launched');
 assert.equal(pro.finalResult.sampleExecutionStarted,false);
 assert.equal(pro.finalResult.sandboxCompleted,false);
 assert.equal(proScannerCalls,0);
 assert.equal(proSandboxCalls,1);
 assert(pro.events.some(e=>e.phase==='preflight'&&e.status==='completed'));
 assert(pro.events.some(e=>e.phase==='sandbox_analysis'&&e.status==='blocked'));
 assert(!pro.events.some(e=>e.phase==='static_scan'));

 // Even an `ok:true` backend response is rejected unless it carries real execution proof.
 const fakeOkManager = new ModelScanPipelineManager({
   scanner:{scanPath:async()=>{throw new Error('scanner must stay unused')}},
   sandbox:sandboxMock({analyzeUntrustedSample:async()=>({ok:true,verdict:'malicious',releaseGrade:true})}),
 });
 const fakeOk=await waitFor(fakeOkManager,fakeOkManager.start('/tmp/fake.js','pro').id);
 assert.equal(fakeOk.finalResult.verdict,'inconclusive');
 assert.equal(fakeOk.finalResult.sandboxStarted,false);
 assert.equal(fakeOk.finalResult.sampleExecutionStarted,false);
 assert.equal(fakeOk.finalResult.sandboxCompleted,false);

 const proMaliciousManager = new ModelScanPipelineManager({
   scanner:{scanPath:async()=>{throw new Error('scanner must stay unused')}},
   sandbox:sandboxMock({analyzeUntrustedSample:async()=>executedResult('malicious',{releaseGrade:true,backend:{backend:'test-sandbox'}})}),
 });
 const proMal=await waitFor(proMaliciousManager,proMaliciousManager.start('/tmp/bad.js','pro').id);
 assert.equal(proMal.finalResult.verdict,'malicious');
 assert.equal(proMal.finalResult.sandboxStarted,true);
 assert.equal(proMal.finalResult.sampleExecutionStarted,true);
 assert.equal(proMal.finalResult.sandboxCompleted,true);

 // Legacy class/API semantics are preserved, but map to Plus.
 const legacy = new ProScanPipelineManager({
   scanner:{scanPath:async()=>({finalVerdict:'safe',contentSha256:'d'.repeat(64),threatIntel:{status:'disabled'}})},
   sandbox:sandboxMock(),
 });
 const legacyResult=await waitFor(legacy,legacy.start('/tmp/legacy.lua').id);
 assert.equal(legacyResult.model,'plus');

 console.log('✓ Model scan pipeline: truthful Sandbox launch/execution proof, Standard/Plus/Pro routing and fail-closed policy passed');
})().catch(e=>{console.error(e.stack||e);process.exit(1)});
