'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const http = require('http');
const { ScannerBridge } = require('../desktop-app/scanner-bridge.js');
const { SandboxController } = require('../desktop-app/sandbox/sandbox-controller.js');
const { startServer } = require('../desktop-app/server.js');

(async()=>{
 const scanner = new ScannerBridge();
 let r = await scanner.scanPath(path.join(__dirname,'corpus','benign-config-read.lua'),'pro');
 assert.equal(r.finalVerdict,'safe');
 r = await scanner.scanPath(path.join(__dirname,'corpus','suspicious-cs-powershell.cs'),'pro');
 assert.notEqual(r.finalVerdict,'safe');

 const sandbox = new SandboxController({timeoutMs:2000,memoryMb:32});
 const probe = await sandbox.selfTest();
 assert.equal(probe.ok,true);
 const denied = await sandbox.analyzeUntrustedSample();
 assert.equal(denied.ok,false);
 assert.equal(denied.code,'SANDBOX_SAMPLE_PATH_REQUIRED');

 const server = await startServer(0);
 const address = server.address();
 assert.equal(address.address,'127.0.0.1');
 const body = await new Promise((resolve,reject)=>{
   http.get({host:'127.0.0.1',port:address.port,path:'/api/status'},res=>{
     const chunks=[];res.on('data',c=>chunks.push(c));res.on('end',()=>resolve(Buffer.concat(chunks).toString('utf8')));
   }).on('error',reject);
 });
 const status=JSON.parse(body);
 assert.equal(status.ok,true);
 assert.equal(status.product,'MalGuard Desktop');
 await new Promise(resolve=>server.close(resolve));
 console.log('✓ Desktop app: real scanner bridge, localhost UI service, guard surface and fail-closed sandbox gateway passed');
})().catch(e=>{console.error(e.stack||e);process.exit(1)});
