'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const http = require('http');
const { ScannerBridge } = require('../desktop-app/scanner-bridge.js');
const { SandboxController } = require('../desktop-app/sandbox/sandbox-controller.js');
const { IsolationBackendRouter } = require('../desktop-app/sandbox/isolation-backend-router.js');
const { startServer, sandbox: productSandbox } = require('../desktop-app/server.js');

function requestJson({ port, method = 'GET', path: requestPath }) {
 return new Promise((resolve,reject)=>{
   const req=http.request({host:'127.0.0.1',port,path:requestPath,method,headers:{'content-length':'0'}},res=>{
     const chunks=[];
     res.on('data',c=>chunks.push(c));
     res.on('end',()=>{
       try{resolve({statusCode:res.statusCode,body:JSON.parse(Buffer.concat(chunks).toString('utf8'))})}
       catch(error){reject(error)}
     });
   });
   req.on('error',reject);
   req.end();
 });
}

(async()=>{
 assert(productSandbox.windowsBackend instanceof IsolationBackendRouter,
   'production Sandbox execution must use the certified multi-backend isolation router');

 const scanner = new ScannerBridge();
 let r = await scanner.scanPath(path.join(__dirname,'corpus','benign-config-read.lua'),'pro');
 assert.equal(r.finalVerdict,'safe');
 r = await scanner.scanPath(path.join(__dirname,'corpus','suspicious-cs-powershell.cs'),'pro');
 assert.notEqual(r.finalVerdict,'safe');

 // Runtime execution remains independently fail-closed regardless of product-level
 // release readiness. Product readiness must never be used as an execution bypass.
 const sandbox = new SandboxController({timeoutMs:2000,memoryMb:32});
 const probe = await sandbox.selfTest();
 assert.equal(probe.localProbeOk,true);
 assert.equal(probe.ok,probe.releaseReady);
 assert.equal(probe.ok,probe.localProbeOk && probe.windowsSandboxReady);
 if(!probe.releaseReady) assert(probe.blockers.length>0);
 const denied = await sandbox.analyzeUntrustedSample();
 assert.equal(denied.ok,false);
 assert.equal(denied.code,'SANDBOX_SAMPLE_PATH_REQUIRED');

 const server = await startServer(0);
 const address = server.address();
 assert.equal(address.address,'127.0.0.1');
 const statusResponse = await requestJson({port:address.port,path:'/api/status'});
 assert.equal(statusResponse.statusCode,200);
 const status=statusResponse.body;
 assert.equal(status.ok,true);
 assert.equal(status.product,'MalGuard Desktop');
 const expectedVersion=fs.readFileSync(path.join(__dirname,'..','DESKTOP-VERSION'),'utf8').trim();
 assert.equal(status.version,expectedVersion);

 const readinessResponse = await requestJson({port:address.port,method:'POST',path:'/api/sandbox/readiness'});
 assert.equal(readinessResponse.statusCode,200);
 const readiness=readinessResponse.body;
 assert.equal(readiness.kind,'malguard-embedded-validation-lab');
 assert.equal(readiness.engineeringValidationPercent,100,JSON.stringify(readiness,null,2));
 assert.equal(readiness.engineeringReady,true,JSON.stringify(readiness,null,2));
 assert.equal(readiness.productImplementationReady,true,JSON.stringify(readiness,null,2));
 assert.equal(readiness.productReadinessPercent,100,JSON.stringify(readiness,null,2));
 assert.equal(readiness.productReleaseReady,true,JSON.stringify(readiness,null,2));
 assert.equal(readiness.artifactReleaseReady,true);
 assert.equal(readiness.fullProductReleaseReady,true);
 assert.equal(readiness.releaseReady,true);
 assert.equal(readiness.deployableReleaseReady,true);
 assert.equal(readiness.deployableReleaseProfile,'standard-plus-pro-runtime-gated');

 for(const plan of ['standard','plus','pro']){
   assert.equal(readiness.releaseProfiles[plan].implementationReady,true);
   assert.equal(readiness.releaseProfiles[plan].releaseReady,true);
   assert.equal(readiness.releaseProfiles[plan].coverage,100);
 }

 assert.equal(readiness.virtualWindowsLab.ok,true);
 assert.equal(readiness.virtualWindowsLab.coveragePercent,100);
 assert.equal(readiness.virtualWindowsLab.safety.realWindowsSandboxClaimed,false);
 assert.equal(readiness.mxcProcessContainer.validated,true);
 assert.equal(readiness.mxcProcessContainer.syntheticOnly,true);
 assert.equal(readiness.mxcProcessContainer.untrustedExecutionCertified,false);
 assert.equal(readiness.runtimeSelfCertification.hostSpecific,true);
 assert.equal(readiness.runtimeSelfCertification.failClosed,true);
 assert.equal(readiness.runtimeSelfCertification.currentHostCertified,readiness.windowsSandboxCertified);
 assert.equal(readiness.runtimeCapabilitiesReadyOnCurrentHost,readiness.windowsSandboxCertified);

 if(readiness.windowsSandboxCertified){
   assert.equal(readiness.releaseProfiles.plus.runtimeSandboxEscalationReady,true);
   assert.equal(readiness.releaseProfiles.pro.runtimeBehavioralExecutionReady,true);
   assert.deepEqual(readiness.lockedCapabilities,[]);
 }else{
   assert.equal(readiness.releaseProfiles.plus.runtimeSandboxEscalationReady,false);
   assert.equal(readiness.releaseProfiles.pro.runtimeBehavioralExecutionReady,false);
   assert(readiness.lockedCapabilities.includes('plus-sandbox-escalation'));
   assert(readiness.lockedCapabilities.includes('pro-behavioral-sandbox'));
   assert(readiness.runtimeBlockers.includes('windows_sandbox_runtime_certification_pending_on_current_host'));
 }

 await new Promise(resolve=>server.close(resolve));
 console.log('✓ Desktop app: product release readiness is 100% while each host independently fail-closes Sandbox execution until local certification passes');
})().catch(e=>{console.error(e.stack||e);process.exit(1)});
