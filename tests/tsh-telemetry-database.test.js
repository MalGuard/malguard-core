'use strict';
const {test,before,after}=require('node:test');
const assert=require('node:assert/strict');const fs=require('fs');const path=require('path');const crypto=require('crypto');
const {PGlite}=require('@electric-sql/pglite');
const {createDatabase}=require('../backend/telemetry/database');
const {buildTelemetryPayload}=require('../desktop-app/diagnostics/telemetry-payload');
const {processEmail}=require('../backend/telemetry/email');
let pg,db;const token=crypto.randomBytes(32).toString('hex');
before(async()=>{pg=new PGlite();await pg.exec(fs.readFileSync(path.join(__dirname,'../migrations/001_opt_in_telemetry.sql'),'utf8'));db=createDatabase(async(q,p)=>(await pg.query(q,p)).rows);});
after(async()=>pg?.close());
async function payload() {return buildTelemetryPayload({settings:{diagnostics:{enabled:true,installationId:crypto.randomUUID(),shareRegion:false}},version:'0.8.0-beta.7',device:async()=>({architecture:'x64',cpuModel:'Synthetic CPU',cpuCores:4,cpuThreads:8,ramBytes:16*2**30})});}
test('Postgres migration creates only disclosed schema, no raw IP or fingerprint columns',async()=>{const r=await pg.query("SELECT column_name FROM information_schema.columns WHERE table_schema='public'");const names=r.rows.map(r=>r.column_name);for(const k of ['ip','raw_ip','mac_address','ssid','latitude','longitude','fingerprint'])assert(!names.includes(k));});
test('registration persists, duplicate produces one email event',async()=>{const p=await payload();assert(await db.register(p,token));assert(await db.register(p,token));const r=await pg.query('SELECT * FROM email_notifications WHERE installation_id=$1',[p.installationId]);assert.equal(r.rows.length,1);assert.equal((await db.detail(p.installationId)).identity_type,'anonymous');});
test('registration cannot take over an existing installation ID',async()=>{const p=await payload();await db.register(p,token);assert.equal(await db.register({...p,cpuModel:'takeover'},'b'.repeat(64)),false);assert.equal((await db.detail(p.installationId)).cpu_model,'Synthetic CPU');});
test('SQL metacharacters persist as inert parameter data',async()=>{const p=await payload();p.cpuModel="'; DROP TABLE installations; --";assert(await db.register(p,token));assert.equal((await db.detail(p.installationId)).cpu_model,p.cpuModel);assert((await db.summary()).total>0);});
test('heartbeat and engine status require installation credential',async()=>{const p=await payload();await db.register(p,token);assert.equal(await db.update(p,'c'.repeat(64),'heartbeat'),false);assert(await db.update(p,token,'heartbeat'));p.capabilities.yaraXAvailable=true;assert(await db.update(p,token,'engine-status'));assert.equal((await db.detail(p.installationId)).yara_x_available,true);});
test('region false clears previously shared region from installation',async()=>{const p=await payload();p.regionConsent=true;p.country='IR';p.region='Tehran';await db.register(p,token);p.regionConsent=false;p.country=null;p.region=null;await db.register(p,token);assert.equal((await db.detail(p.installationId)).country,null);const e=(await pg.query('SELECT status,payload FROM email_notifications WHERE installation_id=$1',[p.installationId])).rows[0];assert.equal(e.status,'failed');assert.deepEqual(e.payload,{});});
test('deletion removes record, capabilities and outbox; replay cannot recreate',async()=>{const p=await payload();await db.register(p,token);assert.equal(await db.unregister(p.installationId,'c'.repeat(64)),false);assert(await db.unregister(p.installationId,token));assert.equal(await db.detail(p.installationId),null);for(const table of ['installation_capabilities','email_notifications'])assert.equal((await pg.query(`SELECT * FROM ${table} WHERE installation_id=$1`,[p.installationId])).rows.length,0);assert.equal(await db.register(p,token),false);assert(await db.unregister(p.installationId,token));});
test('delete arriving before registration prevents delayed registration',async()=>{const p=await payload();assert(await db.unregister(p.installationId,token));assert.equal(await db.register(p,token),false);});
test('database rate limit is shared and bounded without an IP key',async()=>{for(let i=0;i<3;i++)assert(await db.rate('test-scope',3));assert.equal(await db.rate('test-scope',3),false);});
test('admin query never returns credential hashes',async()=>{const p=await payload();await db.register(p,token);assert(!Object.hasOwn(await db.detail(p.installationId),'credential_hash'));assert((await db.list()).every(r=>!Object.hasOwn(r,'credential_hash')));});
test('email outbox sends once across duplicate registration and worker retry',async()=>{
 await pg.query('DELETE FROM installations');const p=await payload();await db.register(p,token);await db.register(p,token);
 let sent=0;const config={env:{RESEND_API_KEY:'synthetic',MALGUARD_INSTALL_NOTIFY_EMAIL:'admin@example.invalid',MALGUARD_INSTALL_FROM_EMAIL:'sender@example.invalid'},fetchImpl:async()=>{sent++;return {ok:true};}};
 await processEmail(db,config);await db.register(p,token);await processEmail(db,config);assert.equal(sent,1);assert.equal((await db.detail(p.installationId)).email_status,'sent');
});
test('email outage retries using same event, database registration survives',async()=>{
 await pg.query('DELETE FROM installations');const p=await payload();await db.register(p,token);let keys=[];
 const env={RESEND_API_KEY:'synthetic',MALGUARD_INSTALL_NOTIFY_EMAIL:'admin@example.invalid',MALGUARD_INSTALL_FROM_EMAIL:'sender@example.invalid'};
 await processEmail(db,{env,fetchImpl:async(u,o)=>{keys.push(o.headers['Idempotency-Key']);throw Error('outage');}});assert(await db.detail(p.installationId));
 await pg.query("UPDATE email_notifications SET last_attempt_at=now()-interval '3 minutes'");
 await processEmail(db,{env,fetchImpl:async(u,o)=>{keys.push(o.headers['Idempotency-Key']);return {ok:true};}});assert.equal(keys.length,2);assert.equal(keys[0],keys[1]);
});
test('retention erases stale installations and expired tombstones',async()=>{const p=await payload();await db.register(p,token);await pg.query("UPDATE installations SET updated_at=now()-interval '91 days' WHERE installation_id=$1",[p.installationId]);await pg.query("INSERT INTO telemetry_deletions VALUES($1,now()-interval '1 day')",[crypto.randomUUID()]);await db.retention();assert.equal(await db.detail(p.installationId),null);assert.equal((await pg.query('SELECT * FROM telemetry_deletions WHERE expires_at<now()')).rows.length,0);});

test('global distributions aggregate disclosed fields only',async()=>{const r=await db.distributions();assert(r.every(x=>typeof x.count==='number'));});
