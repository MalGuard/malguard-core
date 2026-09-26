'use strict';
const crypto=require('crypto');
function matches(value, expected) {
  if(typeof expected!=='string'||!/^[a-f0-9]{64}$/.test(expected)||typeof value!=='string'||value.length<32||value.length>512) return false;
  return crypto.timingSafeEqual(crypto.createHash('sha256').update(value).digest(),Buffer.from(expected,'hex'));
}
function adminAuthorized(req,env=process.env) {
  const h=req.headers?.authorization||'';
  if(!/^Basic [A-Za-z0-9+/]+=*$/.test(h)||h.length>1024) return false;
  const decoded=Buffer.from(h.slice(6),'base64').toString('utf8');
  return decoded.startsWith('admin:') && matches(decoded.slice(6),env.MALGUARD_TELEMETRY_ADMIN_TOKEN_SHA256);
}
function workerAuthorized(req,env=process.env) {
  return matches((req.headers?.authorization||'').replace(/^Bearer /,''),env.MALGUARD_TELEMETRY_WORKER_TOKEN_SHA256);
}
function installationToken(req) {
  const m=/^Bearer ([a-f0-9]{64})$/.exec(req.headers?.authorization||'');
  return m?m[1]:null;
}
module.exports={adminAuthorized,workerAuthorized,installationToken};
