'use strict';

const assert = require('assert');
const { fuseEvidence } = require('../desktop-app/fusion/evidence-fusion-engine.js');
const { runProcess, ENGINE_VERSION } = require('../desktop-app/multiengine/external-engine-runner.js');

function base(verdict='safe') {
  return {
    finalVerdict: verdict,
    sourceIdentity: { sha256:'a'.repeat(64), revalidated:true },
    engineResult: { rulesStatus:'official', peValid:true },
    threatIntel: { status:'hash_not_found' },
  };
}

(async()=>{
  assert.equal(ENGINE_VERSION,'2.0.0');

  const clam=base('safe');
  clam.multiEngine={engines:[
    {name:'clamav',status:'malicious'},
    {name:'yara_x',status:'no_match'},
    {name:'capa',status:'complete'},
  ]};
  const bad=fuseEvidence({localResult:clam,model:'pro'});
  assert.equal(bad.verdict,'malicious');
  assert.equal(bad.basis,'independent_antivirus_detection');

  const yara=base('safe');
  yara.multiEngine={engines:[
    {name:'clamav',status:'clean'},
    {name:'yara_x',status:'matched'},
    {name:'capa',status:'complete'},
  ]};
  const suspicious=fuseEvidence({localResult:yara,model:'pro'});
  assert.equal(suspicious.verdict,'suspicious');
  assert.equal(suspicious.basis,'independent_yara_rule_match');

  const weak=base('safe');
  weak.multiEngine={engines:[
    {name:'clamav',status:'unavailable'},
    {name:'yara_x',status:'unavailable'},
    {name:'capa',status:'complete'},
    {name:'floss',status:'unavailable'},
  ]};
  const guarded=fuseEvidence({localResult:weak,model:'pro'});
  assert.equal(guarded.verdict,'inconclusive');
  assert.equal(guarded.basis,'insufficient_independent_engine_coverage');

  const consensus=base('safe');
  consensus.multiEngine={engines:[
    {name:'clamav',status:'clean'},
    {name:'yara_x',status:'no_match'},
    {name:'capa',status:'complete'},
    {name:'floss',status:'complete'},
  ]};
  const safe=fuseEvidence({localResult:consensus,model:'pro'});
  assert.equal(safe.verdict,'safe');
  assert.equal(safe.layers.independentEngines.completed,4);

  const child=await runProcess(process.execPath,['-e','process.stdout.write("bounded-ok")'],{timeoutMs:5000});
  assert.equal(child.ok,true);
  assert.equal(child.stdout,'bounded-ok');

  const timeout=await runProcess(process.execPath,['-e','setTimeout(()=>{},10000)'],{timeoutMs:50});
  assert.equal(timeout.ok,false);
  assert.equal(timeout.code,'timeout');

  console.log('✓ TSH Stage 2: independent multi-engine arbitration, coverage and process bounding PASS');
})().catch(e=>{console.error(e);process.exit(1);});
