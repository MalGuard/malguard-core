'use strict';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CAPABILITIES=['windowsSandboxAvailable','virtualizationAvailable','defenderAvailable','yaraXAvailable','capaAvailable','malguardAiAvailable'];
const STRINGS=['malguardBuild','deviceManufacturer','deviceModel','cpuModel','gpuModel','windowsEdition','windowsVersion','windowsBuild'];
const BASE=['installationId','diagnosticsConsent','malguardVersion'];
const REGISTER=[...BASE,...STRINGS,'identityType','cpuCores','cpuThreads','ramBytes','architecture','appLanguage','installStatus','firstLaunchStatus','regionConsent','country','region','capabilities'];
function invalid() { throw Object.assign(new Error('invalid-payload'),{status:400}); }
function object(value, keys, required=keys) {
  if (!value || typeof value!=='object' || Array.isArray(value) || Object.keys(value).some(k=>!keys.includes(k)) || required.some(k=>!Object.hasOwn(value,k))) invalid();
}
function string(value,max=160) { if (typeof value!=='string' || !value.length || value.length>max || /[\x00-\x1f\x7f]/.test(value)) invalid(); }
function capabilities(value) { object(value,CAPABILITIES); for (const v of Object.values(value)) if (v!==null && typeof v!=='boolean') invalid(); }
function validatePayload(p,event) {
  const keys=event==='unregister'?['installationId']:event==='register'?REGISTER:event==='engine-status'?[...BASE,'capabilities']:BASE;
  object(p,keys);
  if (!UUID.test(p.installationId)) invalid();
  // UUID spelling must not select a different advisory lock for the same SQL UUID.
  p.installationId=p.installationId.toLowerCase();
  if (event==='unregister') return p;
  if (p.diagnosticsConsent!==true) invalid();
  string(p.malguardVersion,64); if (!/^[0-9A-Za-z._-]+$/.test(p.malguardVersion)) invalid();
  if (event==='engine-status' || event==='register') capabilities(p.capabilities);
  if (event!=='register') return p;
  if (p.identityType!=='anonymous') invalid(); // Never trust a client-asserted account ID.
  for (const key of STRINGS) if (p[key]!==null) string(p[key]);
  for (const [key,max] of [['cpuCores',4096],['cpuThreads',8192],['ramBytes',2**50]]) if (p[key]!==null && (!Number.isSafeInteger(p[key]) || p[key]<1 || p[key]>max)) invalid();
  if (p.cpuCores && p.cpuThreads && p.cpuCores>p.cpuThreads) invalid();
  if (p.architecture!==null && !['x64','arm64','ia32'].includes(p.architecture)) invalid();
  string(p.appLanguage,32); if (!/^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8}){0,3}$/.test(p.appLanguage)) invalid();
  if (!['unknown','succeeded'].includes(p.installStatus) || p.firstLaunchStatus!=='succeeded' || typeof p.regionConsent!=='boolean') invalid();
  if (!p.regionConsent && (p.country!==null || p.region!==null)) invalid();
  if (p.country!==null && (typeof p.country!=='string'||!/^[A-Z]{2}$/.test(p.country))) invalid();
  if (p.region!==null && (typeof p.region!=='string'||!/^[\p{L} .'-]{1,64}$/u.test(p.region))) invalid();
  return p;
}
async function readBody(req) {
  const max=8192;
  if (Number(req.headers?.['content-length'])>max) throw Object.assign(new Error('payload-too-large'),{status:413});
  if (!/^application\/json(?:;|$)/i.test(req.headers?.['content-type']||'')) throw Object.assign(new Error('json-required'),{status:415});
  let body=req.body;
  if (body===undefined) {
    const chunks=[]; let count=0;
    for await (const chunk of req) { count+=Buffer.byteLength(chunk); if(count>max) throw Object.assign(new Error('payload-too-large'),{status:413}); chunks.push(Buffer.from(chunk)); }
    body=Buffer.concat(chunks).toString('utf8');
  }
  if (Buffer.isBuffer(body)) body=body.toString('utf8');
  if (Buffer.byteLength(typeof body==='string'?body:JSON.stringify(body)||'')>max) throw Object.assign(new Error('payload-too-large'),{status:413});
  try { return typeof body==='string'?JSON.parse(body):body; } catch (_) { invalid(); }
}
module.exports={UUID,CAPABILITIES,STRINGS,REGISTER,validatePayload,readBody};
