'use strict';

const assert = require('assert');
const { fuseEvidence, localStaticCoverage } = require('../desktop-app/fusion/evidence-fusion-engine.js');

function local(multi) {
  return {
    finalVerdict:'safe',
    sourceIdentity:{revalidated:true},
    engineResult:{rulesStatus:'official',peValid:true},
    threatIntel:{status:'hash_not_found'},
    multiEngine:multi,
  };
}

const completeClean={
  verdict:'safe',
  riskScore:8,
  coverage:{requiredForSafe:true,complete:true,required:['yaraX','capa','floss']},
  engines:{
    yaraX:{status:'complete',verdict:'safe'},
    capa:{status:'complete',verdict:'safe'},
    floss:{status:'complete',verdict:'safe'},
    defender:{status:'complete',verdict:'safe'},
  },
};

assert.equal(fuseEvidence({localResult:local(completeClean),model:'pro'}).verdict,'safe');
assert.equal(localStaticCoverage(local(completeClean)).fullCoverage,true);

const incomplete=JSON.parse(JSON.stringify(completeClean));
incomplete.coverage.complete=false;
incomplete.engines.capa={status:'timeout',verdict:'inconclusive'};
assert.equal(fuseEvidence({localResult:local(incomplete)}).verdict,'inconclusive');
assert(localStaticCoverage(local(incomplete)).issues.includes('independent_multi_engine_incomplete'));

const suspicious=JSON.parse(JSON.stringify(completeClean));
suspicious.verdict='suspicious';
suspicious.engines.yaraX={status:'complete',verdict:'suspicious'};
assert.equal(fuseEvidence({localResult:local(suspicious)}).verdict,'suspicious');

const malicious=JSON.parse(JSON.stringify(completeClean));
malicious.verdict='malicious';
malicious.engines.defender={status:'complete',verdict:'malicious',detected:true};
assert.equal(fuseEvidence({localResult:local(malicious)}).verdict,'malicious');

const aiCannotOverride=fuseEvidence({
  localResult:local(incomplete),
  aiEvidenceResult:{ok:true,status:'completed',risk:'low',summary:'SAFE'},
});
assert.equal(aiCannotOverride.verdict,'inconclusive');
assert.equal(aiCannotOverride.layers.ai.canPromoteSafe,false);

console.log('✓ Multi-engine Fusion: complete static SAFE gate, incomplete fail-closed, suspicious/malicious precedence and AI non-authority PASS');
