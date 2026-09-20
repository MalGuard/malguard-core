'use strict';

const crypto=require('crypto');
const MAX_BYTES=64*1024;
const ALLOWED_SOURCE=Buffer.from("process.stdout.write(JSON.stringify({marker:'MALGUARD_BENIGN_UPLOAD_V1',runtime:process.version}))\n",'utf8');
const ALLOWED_SHA256=crypto.createHash('sha256').update(ALLOWED_SOURCE).digest('hex');

function strictBase64(value){
 if(typeof value!=='string'||value.length===0||value.length>MAX_BYTES*2)return null;
 if(!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value))return null;
 const b=Buffer.from(value,'base64');return b.length&&b.length<=MAX_BYTES?b:null;
}
async function runBenignUploadedFixture({Sandbox,data}={}){
 if(!Buffer.isBuffer(data)||data.length===0||data.length>MAX_BYTES)throw new Error('invalid-upload');
 const hash=crypto.createHash('sha256').update(data).digest('hex');
 if(hash!==ALLOWED_SHA256||!data.equals(ALLOWED_SOURCE))throw new Error('upload-not-allowlisted');
 if(!Sandbox||typeof Sandbox.create!=='function')throw new Error('sandbox-provider-unavailable');
 let sandbox;
 try{
  sandbox=await Sandbox.create({runtime:'node24',timeout:15000,networkPolicy:'deny-all',persistent:false});
  await sandbox.writeFiles([{path:'uploaded-benign.js',content:data}]);
  const verify=await sandbox.runCommand('node',['-e',"const fs=require('fs'),c=require('crypto'),b=fs.readFileSync('/vercel/sandbox/uploaded-benign.js');process.stdout.write(c.createHash('sha256').update(b).digest('hex'))"]);
  if((await verify.stdout()).trim()!==ALLOWED_SHA256)throw new Error('sandbox-upload-integrity-failed');
  const started=Date.now(),result=await sandbox.runCommand('node',['/vercel/sandbox/uploaded-benign.js']);
  const stdout=await result.stdout();if(stdout.length>4096)throw new Error('output-limit');
  const report=JSON.parse(stdout);if(report.marker!=='MALGUARD_BENIGN_UPLOAD_V1')throw new Error('marker-mismatch');
  return {ok:true,phase:'benign-upload-controlled-execution',report:{marker:report.marker,runtime:report.runtime,durationMs:Date.now()-started,sha256:ALLOWED_SHA256,bytes:data.length},isolation:{ephemeral:true,networkPolicy:'deny-all',persistent:false,secrets:[],publicPorts:[],hostFallback:false,destroyAfterRun:true,execution:'uploaded-allowlisted-benign-fixture-only'}};
 }finally{if(sandbox&&typeof sandbox.stop==='function')await sandbox.stop()}
}
module.exports={MAX_BYTES,ALLOWED_SOURCE,ALLOWED_SHA256,strictBase64,runBenignUploadedFixture};
