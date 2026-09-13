'use strict';
const assert=require('assert');
const fs=require('fs');
const os=require('os');
const path=require('path');
const {spawnSync}=require('child_process');
const ROOT=path.resolve(__dirname,'..');
function runMutant(name,file,from,to,test){
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'malguard-mutant-'));
  try{
    fs.cpSync(ROOT,dir,{recursive:true});
    const target=path.join(dir,file); let s=fs.readFileSync(target,'utf8');
    assert.ok(s.includes(from),name+': mutation target missing');
    fs.writeFileSync(target,s.replace(from,to));
    const r=spawnSync(process.execPath,[path.join(dir,'tests',test)],{encoding:'utf8'});
    assert.notEqual(r.status,0,name+': mutant survived; test suite did not detect weakened guard');
    return true;
  } finally { fs.rmSync(dir,{recursive:true,force:true}); }
}
runMutant('degraded-rules-fail-open','app.js',"engineResult.rulesStatus !== 'official'","engineResult.rulesStatus === 'official'",'final-security-audit.test.js');
runMutant('missing-multilayer-fail-open','app.js',"const preservedVerdict = engineResult && (engineResult.verdict === 'malicious' || engineResult.verdict === 'suspicious')\n      ? engineResult.verdict : 'inconclusive';","const preservedVerdict = engineResult && (engineResult.verdict === 'malicious' || engineResult.verdict === 'suspicious')\n      ? engineResult.verdict : engineResult.verdict;",'final-security-audit.test.js');
runMutant('worker-start-race','scan-worker-client.js',"if (active || scanReserved) throw makeError('WORKER_BUSY'","if (active) throw makeError('WORKER_BUSY'",'web-worker.test.js');
console.log('✓ Mutation security audit: 3/3 security-guard mutants killed');
