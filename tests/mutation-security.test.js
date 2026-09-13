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
    fs.cpSync(ROOT,dir,{
      recursive:true,
      filter:(src)=>{
        const rel=path.relative(ROOT,src);
        return rel !== '.git' && !rel.startsWith('.git'+path.sep);
      },
    });
    const target=path.join(dir,file);
    // Git checkouts on Windows may materialize CRLF. Normalize only the temporary
    // mutant copy so exact security mutations stay portable without weakening them.
    let s=fs.readFileSync(target,'utf8').replace(/\r\n/g,'\n');
    const normalizedFrom=from.replace(/\r\n/g,'\n');
    const normalizedTo=to.replace(/\r\n/g,'\n');
    assert.ok(s.includes(normalizedFrom),name+': mutation target missing');
    fs.writeFileSync(target,s.replace(normalizedFrom,normalizedTo));
    const r=spawnSync(process.execPath,[path.join(dir,'tests',test)],{encoding:'utf8',timeout:60000,windowsHide:true});
    if(r.error && r.error.code==='ETIMEDOUT') throw new Error(name+': mutant verification timed out');
    assert.notEqual(r.status,0,name+': mutant survived; test suite did not detect weakened guard');
    return true;
  } finally { fs.rmSync(dir,{recursive:true,force:true}); }
}
runMutant('degraded-rules-fail-open','app.js',"engineResult.rulesStatus !== 'official'","engineResult.rulesStatus === 'official'",'final-security-audit.test.js');
runMutant('missing-multilayer-fail-open','app.js',"const preservedVerdict = engineResult && (engineResult.verdict === 'malicious' || engineResult.verdict === 'suspicious')\n      ? engineResult.verdict : 'inconclusive';","const preservedVerdict = engineResult && (engineResult.verdict === 'malicious' || engineResult.verdict === 'suspicious')\n      ? engineResult.verdict : engineResult.verdict;",'final-security-audit.test.js');
runMutant('worker-start-race','scan-worker-client.js',"if (active || scanReserved) throw makeError('WORKER_BUSY'","if (active) throw makeError('WORKER_BUSY'",'web-worker.test.js');
console.log('✓ Mutation security audit: 3/3 security-guard mutants killed');
