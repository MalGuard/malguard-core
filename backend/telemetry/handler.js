'use strict';
const {validatePayload,readBody,UUID}=require('./schema.js');
const {databaseFromEnvironment}=require('./database.js');
const {adminAuthorized,workerAuthorized,installationToken}=require('./auth.js');
const {processEmail}=require('./email.js');
const {dashboard}=require('./dashboard.js');

function createHandler({getDatabase=databaseFromEnvironment,env=process.env,fetchImpl=globalThis.fetch}={}) {
  return async function handler(req,res) {
    res.setHeader('Cache-Control','no-store'); res.setHeader('X-Content-Type-Options','nosniff');
    res.setHeader('Content-Security-Policy',"default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'");
    res.setHeader('Referrer-Policy','no-referrer');
    const reply=(status,error)=>res.status(status).json({ok:false,error});
    try {
      // Deployment remains disabled until an operator explicitly configures staging/production.
      if(env.MALGUARD_TELEMETRY_ENABLED!=='1') return reply(503,'telemetry-unavailable');
      if(req.headers?.['x-forwarded-proto']!=='https') return reply(403,'https-required');
      const url=new URL(req.url,'https://telemetry.invalid');
      if(url.pathname.startsWith('/api/v1/admin/')) {
        if(req.method!=='GET') return reply(405,'method-not-allowed');
        if(!adminAuthorized(req,env)) {res.setHeader('WWW-Authenticate','Basic realm="MalGuard admin", charset="UTF-8"');return reply(401,'authentication-required');}
        const db=getDatabase(); if(!await db.rate('admin',60)) return reply(429,'rate-limited');
        const id=url.pathname.split('/')[5]||url.searchParams.get('id');
        if(id && !UUID.test(id)) return reply(400,'invalid-id');
        const offset=Number(url.searchParams.get('offset')||0);
        if(!Number.isSafeInteger(offset)||offset<0||offset>100000) return reply(400,'invalid-offset');
        const result=id?{detail:await db.detail(id)}:{summary:await db.summary(),rows:await db.list(offset),distributions:await db.distributions(),offset};
        if(id&&!result.detail) return reply(404,'not-found');
        if(url.searchParams.get('view')==='dashboard') {res.setHeader('Content-Type','text/html; charset=utf-8');return res.status(200).send(dashboard(result));}
        return res.status(200).json({ok:true,...result});
      }
      if(req.method!=='POST') return reply(405,'method-not-allowed');
      if(url.pathname==='/api/v1/installations/maintenance') {
        if(!workerAuthorized(req,env)) return reply(401,'authentication-required');
        const db=getDatabase(); if(!await db.rate('maintenance',30)) return reply(429,'rate-limited');
        await db.retention(); const result=await processEmail(db,{fetchImpl,env});
        return res.status(200).json({ok:true,...result});
      }
      const event=url.pathname.split('/').pop();
      if(!['register','heartbeat','engine-status','unregister'].includes(event)) return reply(404,'not-found');
      const token=installationToken(req); if(!token) return reply(401,'authentication-required');
      const p=validatePayload(await readBody(req),event);
      const db=getDatabase(); if(!await db.rate(event==='unregister'?'privacy-control':'ingest',event==='unregister'?600:120)) return reply(429,'rate-limited');
      const ok=event==='register'?await db.register(p,token):event==='unregister'?await db.unregister(p.installationId,token):await db.update(p,token,event);
      if(!ok) return reply(403,'registration-not-authorized');
      // Email is a separate authenticated outbox worker, never on the installer critical path.
      return res.status(200).json({ok:true});
    } catch(error) { return reply([400,413,415].includes(error.status)?error.status:503,[400,413,415].includes(error.status)?error.message:'telemetry-unavailable'); }
  };
}
module.exports={createHandler};
