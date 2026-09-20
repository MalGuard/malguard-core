'use strict';
const assert=require('assert');const {validateInspectionFile,createInspectionJob,MAX_INSPECTION_BYTES}=require('../cloud-sandbox/job-policy');
assert.equal(validateInspectionFile(Buffer.alloc(0)).ok,false);assert.equal(validateInspectionFile(Buffer.alloc(MAX_INSPECTION_BYTES+1)).ok,false);
const j=createInspectionJob(Buffer.from('hello'));assert.equal(j.accepted,true);assert.equal(j.isolation.networkPolicy,'deny-all');assert.equal(j.isolation.hostFallback,false);assert.equal(j.isolation.destroyAfterRun,true);assert.equal(j.isolation.execution,'inspection-only');
console.log('✓ bounded file inspection policy is fail-closed and isolated');
