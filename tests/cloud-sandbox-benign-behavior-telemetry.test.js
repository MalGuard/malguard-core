'use strict';
const assert=require('assert');
const {PROGRAM,PROGRAM_SHA256,ARTIFACT,ARTIFACT_SHA256,strictBase64,runBenignBehaviorTelemetry}=require('../cloud-sandbox/benign-behavior-telemetry');

assert(strictBase64(PROGRAM.toString('base64')).equals(PROGRAM));
assert.equal(strictBase64('%%%'),null);

class FakeSandbox{
 static last;
 static async create(opts){
  assert.equal(opts.networkPolicy,'deny-all');
  assert.equal(opts.persistent,false);
  assert.equal(opts.timeout,15000);
  return FakeSandbox.last=new FakeSandbox();
 }
 async writeFiles(files){assert(files[0].content.equals(PROGRAM))}
 async runCommand(cmd,args){
  assert.equal(cmd,'node');
  if(args[0]==='-e'&&args[1].includes("uploaded-benign-behavior.js"))return{stdout:async()=>PROGRAM_SHA256};
  if(args[0]==='-e'&&args[1].includes("behavior-output.txt"))return{stdout:async()=>JSON.stringify({path:'behavior-output.txt',bytes:ARTIFACT.length,sha256:ARTIFACT_SHA256})};
  return{stdout:async()=>JSON.stringify({marker:'MALGUARD_BEHAVIOR_TELEMETRY_V1',runtime:'v24-test'})};
 }
 async stop(){this.stopped=true}
}

(async()=>{
 const r=await runBenignBehaviorTelemetry({Sandbox:FakeSandbox,data:PROGRAM});
 assert.equal(r.ok,true);
 assert.equal(r.phase,'benign-upload-behavior-telemetry');
 assert.equal(r.report.marker,'MALGUARD_BEHAVIOR_TELEMETRY_V1');
 assert.equal(r.report.filesystem.created[0].sha256,ARTIFACT_SHA256);
 assert.equal(r.isolation.networkPolicy,'deny-all');
 assert.equal(r.isolation.execution,'uploaded-allowlisted-benign-behavior-fixture-only');
 assert(FakeSandbox.last.stopped);
 await assert.rejects(()=>runBenignBehaviorTelemetry({Sandbox:FakeSandbox,data:Buffer.from('other')}),/upload-not-allowlisted/);
 console.log('✓ benign behavior telemetry captures bounded output and filesystem artifact');
})().catch(e=>{console.error(e);process.exit(1)});
