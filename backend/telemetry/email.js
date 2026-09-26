'use strict';
const {validatePayload}=require('./schema.js');
function emailMessage(p) {
  validatePayload(p,'register');
  return {
    subject:`New MalGuard Installation · ${p.deviceModel||'Unknown model'} · ${p.malguardVersion}`,
    text:'A user chose to share MalGuard installation diagnostics.\n\n'+Object.entries(p).map(([k,v])=>`${k}: ${typeof v==='object'?JSON.stringify(v):v}`).join('\n')+'\n\nRegistration time is recorded by the server; installer time is not inferred.'
  };
}
async function processEmail(db,{fetchImpl=globalThis.fetch,env=process.env}={}) {
  if(!env.RESEND_API_KEY||!env.MALGUARD_INSTALL_NOTIFY_EMAIL||!env.MALGUARD_INSTALL_FROM_EMAIL) return {processed:false,reason:'not-configured'};
  const event=await db.claimEmail();
  if(!event) return {processed:false};
  let ok=false;
  try {
    const message=emailMessage(event.payload);
    if(!await db.emailExists(event.id)) return {processed:false,reason:'deleted'};
    const response=await fetchImpl('https://api.resend.com/emails',{method:'POST',redirect:'error',signal:AbortSignal.timeout(5000),headers:{authorization:`Bearer ${env.RESEND_API_KEY}`,'content-type':'application/json','Idempotency-Key':`malguard-install/${event.id}`},body:JSON.stringify({from:env.MALGUARD_INSTALL_FROM_EMAIL,to:[env.MALGUARD_INSTALL_NOTIFY_EMAIL],...message})});
    ok=response.ok===true;
  } catch (_) { /* Only a fixed failure code is persisted; provider data and secrets are not logged. */ }
  await db.finishEmail(event.id,ok);
  return {processed:true,sent:ok};
}
module.exports={emailMessage,processEmail};
