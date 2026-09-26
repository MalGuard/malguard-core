'use strict';
const assert=require('assert');
const {recordFirstSuccessfulLaunch,buildBeaconUrl}=require('../desktop-app/metrics/first-launch-counter');
(async()=>{
 assert(buildBeaconUrl('0.8.0-beta.7','x64').startsWith('https://github.com/'));
 let calls=0;
 for(const enabled of [false,true]) {
  const r=await recordFirstSuccessfulLaunch({platform:'win32',ci:false,requirePackaged:false,consent:{canSendDiagnostics:()=>enabled},fetchImpl:()=>{calls++;}});
  assert.equal(r.counted,false);
 }
 assert.equal(calls,0);
 console.log('Legacy first-launch analytics retired: zero requests with or without consent');
})().catch(e=>{console.error(e);process.exit(1);});
