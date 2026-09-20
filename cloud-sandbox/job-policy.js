'use strict';

const crypto = require('crypto');
const MAX_INSPECTION_BYTES = 8 * 1024 * 1024;
const ALLOWED_FIXTURE = Buffer.from('MALGUARD_SAFE_SANDBOX_FIXTURE_V1\n', 'utf8');

function sha256(data){ return crypto.createHash('sha256').update(data).digest('hex'); }
function validateInspectionFile(data){
  if(!Buffer.isBuffer(data)) throw new TypeError('file must be a Buffer');
  if(data.length===0 || data.length>MAX_INSPECTION_BYTES) return {ok:false,reason:'size'};
  return {ok:true,sha256:sha256(data),bytes:data.length};
}
function createInspectionJob(data){
  const file=validateInspectionFile(data);
  if(!file.ok) return {accepted:false,...file};
  return {accepted:true,jobId:crypto.randomUUID(),file,isolation:{ephemeral:true,networkPolicy:'deny-all',publicPorts:[],secrets:[],timeoutMs:30000,hostFallback:false,destroyAfterRun:true,execution:'inspection-only'}};
}
function validateSafeFixture(data){
  const v=validateInspectionFile(data); if(!v.ok)return v;
  if(!data.equals(ALLOWED_FIXTURE))return {ok:false,reason:'safe-fixture-only'};
  return v;
}
function createIsolationJob(data){const v=validateSafeFixture(data);if(!v.ok)return {accepted:false,...v};return createInspectionJob(data)}
module.exports={ALLOWED_FIXTURE,MAX_INSPECTION_BYTES,validateInspectionFile,createInspectionJob,validateSafeFixture,createIsolationJob};
