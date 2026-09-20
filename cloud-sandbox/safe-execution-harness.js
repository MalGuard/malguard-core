'use strict';

const crypto=require('crypto');
const SAFE_PROGRAM=Buffer.from("process.stdout.write(JSON.stringify({marker:'MALGUARD_SAFE_EXEC_V1',pid:process.pid,node:process.version}))\n",'utf8');
// Production rollout marker: safe execution harness v1.
const SAFE_SHA256=crypto.createHash('sha256').update(SAFE_PROGRAM).digest('hex');

async function runSafeExecutionFixture({Sandbox}={}){
 if(!Sandbox||typeof Sandbox.create!=='function')throw new Error('sandbox-provider-unavailable');
 let sandbox;
 try{
  sandbox=await Sandbox.create({runtime:'node24',timeout:15000,networkPolicy:'deny-all',persistent:false});
  await sandbox.writeFiles([{path:'safe-exec.js',content:SAFE_PROGRAM}]);
  const verify=await sandbox.runCommand('node',['-e',"const fs=require('fs'),c=require('crypto'),b=fs.readFileSync('/vercel/sandbox/safe-exec.js');process.stdout.write(c.createHash('sha256').update(b).digest('hex'))"]);
  if((await verify.stdout()).trim()!==SAFE_SHA256)throw new Error('fixture-integrity-failed');
  const started=Date.now();
  const result=await sandbox.runCommand('node',['/vercel/sandbox/safe-exec.js']);
  const report=JSON.parse(await result.stdout());
  if(report.marker!=='MALGUARD_SAFE_EXEC_V1')throw new Error('execution-marker-mismatch');
  return {ok:true,phase:'safe-execution-fixture',report:{marker:report.marker,runtime:report.node,durationMs:Date.now()-started,fixtureSha256:SAFE_SHA256},isolation:{ephemeral:true,networkPolicy:'deny-all',persistent:false,secrets:[],publicPorts:[],hostFallback:false,destroyAfterRun:true,execution:'allowlisted-safe-fixture-only'}};
 }finally{if(sandbox&&typeof sandbox.stop==='function')await sandbox.stop()}
}
module.exports={SAFE_PROGRAM,SAFE_SHA256,runSafeExecutionFixture};
