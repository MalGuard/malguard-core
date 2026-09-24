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
  deepStaticFallbackVerdict,
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
 assert.equal(deepStaticFallbackVerdict({finalVerdict:'malicious'}),'malicious');
 assert.equal(deepStaticFallbackVerdict({finalVerdict:'suspicious'}),'suspicious');
 assert.equal(deepStaticFallbackVerdict({finalVerdict:'safe'}),'inconclusive','static fallback must not claim SAFE without dynamic execution');

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

 // Plus performs deep analysis first, then uses the same evidence as a no-execution fallback if Sandbox is unavailable.
 let plusMode = null;
 let plusSandboxCalls = 0;
 const plusSafeManager = new ModelScanPipelineManager({
   scanner:{scanPath:async(_p,mode)=>{plusMode=mode;return {finalVerdict:'safe',contentSha256:'b'.repeat(64),scriptAnalysis:{finalVerdict:'safe'},threatIntel:{status:'hash_not_found',source:'live'}}}},
   sandbox:sandboxMock({analyzeUntrustedSample:async()=>{plusSandboxCalls++;return executedResult('safe')}}),
 });
 const plusSafe=await waitFor(plusSafeManager,plusSafeManager.start('/tmp/safe.lua','plus').id);
 assert.equal(plusSafe.finalResult.model,'plus');
 assert.equal(plusSafe.finalResult.verdict,'safe');
 assert.equal(plusSafe.finalResult.sandboxRequested,true);
 assert.equal(plusMode,'pro');
 assert.equal(plusSandboxCalls,1);
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
 assert.equal(plusSus.finalResult.fallbackUsed,true);
 assert.equal(plusSus.finalResult.completionState,'deep_static_fallback');
 assert(plusSus.events.some(e=>e.phase==='sandbox_decision'&&e.status==='warning'));
 assert(plusSus.events.some(e=>e.phase==='fallback_analysis'&&e.status==='completed'));

 // Pro still prefers direct Sandbox. Only when real Sandbox execution is unavailable does it invoke deep static fallback.
 let proScannerCalls = 0;
 let proSandboxCalls = 0;
 const proManager = new ModelScanPipelineManager({
   scanner:{scanPath:async(_p,mode)=>{proScannerCalls++;assert.equal(mode,'pro');return {finalVerdict:'suspicious',contentSha256:'e'.repeat(64),threatIntel:{status:'hash_not_found',source:'cache'}}}},
   sandbox:sandboxMock({analyzeUntrustedSample:async()=>{proSandboxCalls++;return {ok:false,verdict:'inconclusive',code:'HARDENED_SANDBOX_ACCEPTANCE_PENDING',sandboxLaunched:false,sampleExecutionStarted:false}}}),
 });
 const pro=await waitFor(proManager,proManager.start('/tmp/sample.js','pro').id);
 assert.equal(pro.finalResult.model,'pro');
 assert.equal(pro.finalResult.verdict,'suspicious');
 assert.equal(pro.finalResult.sandboxRequested,true);
 assert.equal(pro.finalResult.sandboxStarted,false,'requesting Sandbox is not evidence that Windows Sandbox actually launched');
 assert.equal(pro.finalResult.sampleExecutionStarted,false);
 assert.equal(pro.finalResult.sandboxCompleted,false);
 assert.equal(pro.finalResult.fallbackUsed,true);
 assert.equal(pro.finalResult.fallbackMode,'deep_static_no_execution');
 assert.equal(proScannerCalls,1);
 assert.equal(proSandboxCalls,1);
 assert(pro.events.some(e=>e.phase==='preflight'&&e.status==='completed'));
 assert(pro.events.some(e=>e.phase==='sandbox_analysis'&&e.status==='blocked'));
 assert(pro.events.some(e=>e.phase==='fallback_analysis'&&e.status==='completed'));
 assert(!pro.events.some(e=>e.phase==='static_scan'));

 // An `ok:true` backend response without real execution proof cannot influence verdict; fallback remains fail-closed.
 const fakeOkManager = new ModelScanPipelineManager({
   scanner:{scanPath:async()=>({finalVerdict:'safe',contentSha256:'1'.repeat(64),threatIntel:{status:'disabled'}})},
   sandbox:sandboxMock({analyzeUntrustedSample:async()=>({ok:true,verdict:'malicious',releaseGrade:true})}),
 });
 const fakeOk=await waitFor(fakeOkManager,fakeOkManager.start('/tmp/fake.js','pro').id);
 assert.equal(fakeOk.finalResult.verdict,'inconclusive');
 assert.equal(fakeOk.finalResult.sandboxStarted,false);
 assert.equal(fakeOk.finalResult.sampleExecutionStarted,false);
 assert.equal(fakeOk.finalResult.sandboxCompleted,false);
 assert.equal(fakeOk.finalResult.fallbackUsed,true);

 // When real Sandbox succeeds, Pro remains direct-Sandbox and the fallback scanner is not used.
 let successfulProScannerCalls = 0;
 const proMaliciousManager = new ModelScanPipelineManager({
   scanner:{scanPath:async()=>{successfulProScannerCalls++;return {finalVerdict:'inconclusive'}}},
   sandbox:sandboxMock({analyzeUntrustedSample:async()=>executedResult('malicious',{releaseGrade:true,backend:{backend:'test-sandbox'}})}),
 });
 const proMal=await waitFor(proMaliciousManager,proMaliciousManager.start('/tmp/bad.js','pro').id);
 assert.equal(proMal.finalResult.verdict,'malicious');
 assert.equal(proMal.finalResult.sandboxStarted,true);
 assert.equal(proMal.finalResult.sampleExecutionStarted,true);
 assert.equal(proMal.finalResult.sandboxCompleted,true);
 assert.equal(successfulProScannerCalls,0);

 // Legacy class/API semantics are preserved, but map to Plus.
 const legacy = new ProScanPipelineManager({
   scanner:{scanPath:async()=>({finalVerdict:'safe',contentSha256:'d'.repeat(64),threatIntel:{status:'disabled'}})},
   sandbox:sandboxMock(),
 });
 const legacyResult=await waitFor(legacy,legacy.start('/tmp/legacy.lua').id);
 assert.equal(legacyResult.model,'plus');

 console.log('✓ Model scan pipeline: real Sandbox preferred, deep static no-execution fallback, truthful execution proof and fail-closed verdict policy passed');
})().catch(e=>{console.error(e.stack||e);process.exit(1)});
