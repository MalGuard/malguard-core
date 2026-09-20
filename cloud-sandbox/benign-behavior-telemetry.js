'use strict';

const crypto=require('crypto');
const MAX_BYTES=64*1024;
const ARTIFACT=Buffer.from('MALGUARD_BEHAVIOR_ARTIFACT_V1\n','utf8');
const PROGRAM=Buffer.from(
  "const fs=require('fs');"+
  "fs.writeFileSync('/vercel/sandbox/behavior-output.txt','MALGUARD_BEHAVIOR_ARTIFACT_V1\\n');"+
  "process.stdout.write(JSON.stringify({marker:'MALGUARD_BEHAVIOR_TELEMETRY_V1',runtime:process.version}));\n",
  'utf8'
);
const PROGRAM_SHA256=crypto.createHash('sha256').update(PROGRAM).digest('hex');
const ARTIFACT_SHA256=crypto.createHash('sha256').update(ARTIFACT).digest('hex');

function strictBase64(value){
 if(typeof value!=='string'||value.length===0||value.length>MAX_BYTES*2)return null;
 if(!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value))return null;
 const b=Buffer.from(value,'base64');return b.length&&b.length<=MAX_BYTES?b:null;
}

async function runBenignBehaviorTelemetry({Sandbox,data}={}){
 if(!Buffer.isBuffer(data)||data.length===0||data.length>MAX_BYTES)throw new Error('invalid-upload');
 const hash=crypto.createHash('sha256').update(data).digest('hex');
 if(hash!==PROGRAM_SHA256||!data.equals(PROGRAM))throw new Error('upload-not-allowlisted');
 if(!Sandbox||typeof Sandbox.create!=='function')throw new Error('sandbox-provider-unavailable');
 let sandbox;
 try{
  sandbox=await Sandbox.create({runtime:'node24',timeout:15000,networkPolicy:'deny-all',persistent:false});
  await sandbox.writeFiles([{path:'uploaded-benign-behavior.js',content:data}]);
  const verify=await sandbox.runCommand('node',['-e',"const fs=require('fs'),c=require('crypto'),b=fs.readFileSync('/vercel/sandbox/uploaded-benign-behavior.js');process.stdout.write(c.createHash('sha256').update(b).digest('hex'))"]);
  if((await verify.stdout()).trim()!==PROGRAM_SHA256)throw new Error('sandbox-upload-integrity-failed');

  const started=Date.now();
  const result=await sandbox.runCommand('node',['/vercel/sandbox/uploaded-benign-behavior.js']);
  const stdout=await result.stdout();
  if(stdout.length>4096)throw new Error('output-limit');
  const execution=JSON.parse(stdout);
  if(execution.marker!=='MALGUARD_BEHAVIOR_TELEMETRY_V1')throw new Error('marker-mismatch');

  const inspectScript="const fs=require('fs'),c=require('crypto'),p='/vercel/sandbox/behavior-output.txt',b=fs.readFileSync(p);process.stdout.write(JSON.stringify({path:'behavior-output.txt',bytes:b.length,sha256:c.createHash('sha256').update(b).digest('hex')}))";
  const inspected=await sandbox.runCommand('node',['-e',inspectScript]);
  const fsOut=await inspected.stdout();
  if(fsOut.length>4096)throw new Error('telemetry-output-limit');
  const artifact=JSON.parse(fsOut);
  if(artifact.sha256!==ARTIFACT_SHA256||artifact.bytes!==ARTIFACT.length)throw new Error('artifact-integrity-failed');

  return {
   ok:true,
   phase:'benign-upload-behavior-telemetry',
   report:{
    marker:execution.marker,
    process:{runtime:execution.runtime,durationMs:Date.now()-started},
    upload:{sha256:PROGRAM_SHA256,bytes:data.length},
    output:{stdoutBytes:Buffer.byteLength(stdout,'utf8'),bounded:true},
    filesystem:{created:[artifact]}
   },
   isolation:{ephemeral:true,networkPolicy:'deny-all',persistent:false,secrets:[],publicPorts:[],hostFallback:false,destroyAfterRun:true,sandboxTimeoutMs:15000,execution:'uploaded-allowlisted-benign-behavior-fixture-only'}
  };
 }finally{if(sandbox&&typeof sandbox.stop==='function')await sandbox.stop()}
}

module.exports={MAX_BYTES,PROGRAM,PROGRAM_SHA256,ARTIFACT,ARTIFACT_SHA256,strictBase64,runBenignBehaviorTelemetry};
