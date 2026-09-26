'use strict';

const assert = require('assert');
const { ModelScanPipelineManager } = require('../desktop-app/pro-scan-pipeline.js');
const { fuseEvidence } = require('../desktop-app/fusion/evidence-fusion-engine.js');

const sleep = ms => new Promise(r => setTimeout(r, ms));

async function finished(manager, id) {
  for (let i = 0; i < 300; i++) {
    const snap = manager.snapshot(id);
    if (snap && ['completed','failed'].includes(snap.state)) return snap;
    await sleep(10);
  }
  throw new Error('TSH Pro timed out waiting for scan completion');
}

function strongLocal(verdict='safe') {
  return {
    finalVerdict: verdict,
    sourceIdentity: { revalidated:true, sha256:'a'.repeat(64) },
    engineResult: { rulesStatus:'official', peValid:true },
    threatIntel: { status:'unavailable' },
    multiEngine: {
      engines: [
        { name:'yara_x', status:'no_match' },
        { name:'capa', status:'complete' },
        { name:'microsoft_defender', status:'clean' },
        { name:'floss', status:'unavailable' },
        { name:'clamav', status:'unavailable' },
      ]
    }
  };
}

function makeManager({ preflight, analyze, localResult, aiResult }) {
  let scannerCalls = 0;
  const scanner = {
    async scanPath() {
      scannerCalls++;
      return JSON.parse(JSON.stringify(localResult));
    }
  };
  const sandbox = {
    async preflightSample() { return JSON.parse(JSON.stringify(preflight)); },
    async analyzeUntrustedSample() { return JSON.parse(JSON.stringify(analyze)); },
  };
  const aiEvidence = {
    capabilities(){ return { available:true }; },
    async analyze(){ return JSON.parse(JSON.stringify(aiResult)); },
  };
  const manager = new ModelScanPipelineManager({ scanner, sandbox, aiEvidence });
  return { manager, calls:()=>scannerCalls };
}

(async()=>{
  console.log('TSH PRO / Sandboxless adversarial acceptance');
  console.log('Safety: synthetic benign evidence only; no malware execution');

  // 1. Critical acceptance: Sandbox missing at preflight MUST NOT bypass local scan.
  {
    const h = makeManager({
      preflight:{ ok:false, code:'SANDBOX_UNAVAILABLE' },
      analyze:{ ok:false, code:'SANDBOX_UNAVAILABLE' },
      localResult:strongLocal('safe'),
      aiResult:{ ok:false, available:false, status:'provider_unavailable' },
    });
    const started = h.manager.start('synthetic-safe.dll','pro',{allowCloudFallback:false,allowAiEvidence:true});
    const snap = await finished(h.manager, started.id);
    assert.equal(h.calls(), 1, 'Pro must execute the local scanner even when Sandbox preflight is unavailable');
    assert.equal(snap.finalResult.fallbackUsed, true);
    assert.equal(snap.finalResult.dynamicAnalysisUnavailable, true);
    assert.equal(snap.finalResult.verdict, 'safe', 'strong independent local evidence must not become INCONCLUSIVE solely because Sandbox is missing');
    assert.equal(snap.finalResult.fusion.layers.independentEngines.completed >= 2, true);
  }

  // 2. Sandbox passes preflight but disappears before execution: local fallback must still decide.
  {
    const h = makeManager({
      preflight:{ ok:true, sha256:'b'.repeat(64), size:4096, extension:'.dll' },
      analyze:{ ok:false, code:'SANDBOX_UNAVAILABLE', sandboxLaunched:false, sampleExecutionStarted:false },
      localResult:strongLocal('safe'),
      aiResult:{ ok:true, available:true, status:'complete', risk:'high' },
    });
    const started = h.manager.start('synthetic-safe-2.dll','pro',{allowCloudFallback:false,allowAiEvidence:true});
    const snap = await finished(h.manager, started.id);
    assert.equal(h.calls(), 1);
    assert.equal(snap.finalResult.fallbackUsed, true);
    assert.equal(snap.finalResult.verdict, 'safe');
    assert.equal(snap.finalResult.fusion.layers.ai.advisoryOnly, true);
    assert.equal(snap.finalResult.fusion.layers.ai.canPromoteSafe, false);
  }

  // 3. Suspicious local evidence must remain suspicious without Sandbox.
  {
    const suspicious = strongLocal('suspicious');
    const h = makeManager({
      preflight:{ ok:false, code:'SANDBOX_UNAVAILABLE' },
      analyze:{ ok:false },
      localResult:suspicious,
      aiResult:{ ok:false, available:false, status:'offline' },
    });
    const started=h.manager.start('synthetic-suspicious.asi','pro',{allowCloudFallback:false,allowAiEvidence:true});
    const snap=await finished(h.manager,started.id);
    assert.equal(snap.finalResult.verdict,'suspicious');
  }

  // 4. Malicious local evidence must remain malicious without Sandbox.
  {
    const malicious = strongLocal('malicious');
    const h = makeManager({
      preflight:{ ok:false, code:'SANDBOX_UNAVAILABLE' },
      analyze:{ ok:false },
      localResult:malicious,
      aiResult:{ ok:false, available:false, status:'offline' },
    });
    const started=h.manager.start('synthetic-malicious.dll','pro',{allowCloudFallback:false,allowAiEvidence:false});
    const snap=await finished(h.manager,started.id);
    assert.equal(snap.finalResult.verdict,'malicious');
  }

  // 5. YARA-X conflict must block SAFE even if base scanner says safe.
  {
    const local = strongLocal('safe');
    local.multiEngine.engines[0].status='matched';
    const fused=fuseEvidence({localResult:local,model:'pro'});
    assert.equal(fused.verdict,'suspicious');
    assert.equal(fused.basis,'independent_yara_rule_match');
  }

  // 6. Known-malicious reputation must dominate lack of Sandbox.
  {
    const local=strongLocal('safe');
    local.threatIntel={status:'known_malicious',source:'synthetic-test'};
    const fused=fuseEvidence({localResult:local,model:'pro'});
    assert.equal(fused.verdict,'malicious');
  }

  // 7. Pro SAFE must require at least two independent engines. Zero is NOT success.
  {
    const local=strongLocal('safe');
    delete local.multiEngine;
    const fused=fuseEvidence({localResult:local,model:'pro'});
    assert.equal(fused.verdict,'inconclusive','Pro must fail closed when independent engines did not run at all');
  }

  // 8. One independent engine is insufficient for Pro SAFE.
  {
    const local=strongLocal('safe');
    local.multiEngine.engines=[
      {name:'capa',status:'complete'},
      {name:'yara_x',status:'unavailable'},
      {name:'microsoft_defender',status:'unavailable'},
    ];
    const fused=fuseEvidence({localResult:local,model:'pro'});
    assert.equal(fused.verdict,'inconclusive');
    assert.equal(fused.basis,'insufficient_independent_engine_coverage');
  }

  // 9. AI outage must not erase strong local evidence.
  {
    const h=makeManager({
      preflight:{ok:true,sha256:'c'.repeat(64),size:4096,extension:'.dll'},
      analyze:{ok:false,code:'SANDBOX_UNAVAILABLE'},
      localResult:strongLocal('safe'),
      aiResult:{ok:false,available:false,status:'bridge_error'},
    });
    const started=h.manager.start('synthetic-ai-offline.dll','pro',{allowCloudFallback:false,allowAiEvidence:true});
    const snap=await finished(h.manager,started.id);
    assert.equal(snap.finalResult.verdict,'safe');
  }

  // 10. Every sandboxless SAFE must explicitly disclose missing behavioral proof.
  {
    const local=strongLocal('safe');
    const fused=fuseEvidence({localResult:local,model:'pro'});
    assert.equal(fused.verdict,'safe');
    assert.equal(fused.safeClaim.absoluteGuarantee,false);
    assert.equal(fused.limitations.includes('behavioral_execution_evidence_unavailable'),true);
  }

  console.log('✓ TSH PRO PASS: Pro scans locally without Sandbox, avoids false INCONCLUSIVE, and still fails closed on weak coverage.');
})().catch(err=>{
  console.error('✗ TSH PRO FAIL');
  console.error(err && err.stack || err);
  process.exit(1);
});
