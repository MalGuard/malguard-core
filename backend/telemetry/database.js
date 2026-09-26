'use strict';
const { createHash }=require('crypto');
const COLUMNS={identityType:'identity_type',malguardVersion:'malguard_version',malguardBuild:'malguard_build',deviceManufacturer:'device_manufacturer',deviceModel:'device_model',cpuModel:'cpu_model',cpuCores:'cpu_cores',cpuThreads:'cpu_threads',ramBytes:'ram_bytes',gpuModel:'gpu_model',windowsEdition:'windows_edition',windowsVersion:'windows_version',windowsBuild:'windows_build',architecture:'architecture',appLanguage:'app_language',diagnosticsConsent:'diagnostics_consent',regionConsent:'region_consent',country:'country',region:'region',installStatus:'install_status',firstLaunchStatus:'first_launch_status'};
const CAPS={windowsSandboxAvailable:'windows_sandbox_available',virtualizationAvailable:'virtualization_available',defenderAvailable:'defender_available',yaraXAvailable:'yara_x_available',capaAvailable:'capa_available',malguardAiAvailable:'malguard_ai_available'};
const hash=token=>createHash('sha256').update(token).digest('hex');
function createDatabase(query, lockedQuery = (id, text, params) => query(text, params)) {
  async function capabilities(p) {
    const fields=Object.values(CAPS), values=Object.keys(CAPS).map(k=>p.capabilities[k]);
    // Called within the same SQL statement as an authenticated parent update (see update).
    return {fields,values};
  }
  return {
    async rate(scope,limit=120) {
      const rows=await query(`INSERT INTO telemetry_rate_limits(scope,window_start,requests) VALUES($1,date_trunc('minute',now()),1)
        ON CONFLICT(scope) DO UPDATE SET window_start=date_trunc('minute',now()), requests=CASE WHEN telemetry_rate_limits.window_start<date_trunc('minute',now()) THEN 1 ELSE telemetry_rate_limits.requests+1 END RETURNING requests`,[scope]);
      return rows[0].requests<=limit;
    },
    async register(p,token) {
      const names=Object.values(COLUMNS), vals=Object.keys(COLUMNS).map(k=>p[k]);
      const cap=await capabilities(p);
      const params=[p.installationId,hash(token),...vals,JSON.stringify(p),...cap.values];
      const payloadIndex=3+vals.length, capStart=payloadIndex+1;
      const rows=await lockedQuery(p.installationId, `WITH parent AS (
        INSERT INTO installations(installation_id,credential_hash,${names.join(',')})
        SELECT $1::uuid,$2,${vals.map((_,i)=>'$'+(i+3)).join(',')}
        WHERE NOT EXISTS(SELECT 1 FROM telemetry_deletions WHERE installation_id=$1::uuid AND expires_at>now())
        ON CONFLICT(installation_id) DO UPDATE SET ${names.map((n,i)=>n+'=$'+(i+3)).join(',')},updated_at=now()
        WHERE installations.credential_hash=$2 RETURNING installation_id
      ), caps AS (
        INSERT INTO installation_capabilities(installation_id,${cap.fields.join(',')}) SELECT installation_id,${cap.values.map((_,i)=>'$'+(capStart+i)).join(',')} FROM parent
        ON CONFLICT(installation_id) DO UPDATE SET ${cap.fields.map(n=>n+'=EXCLUDED.'+n).join(',')},updated_at=now()
      ), cancel_changed_region AS (
        UPDATE email_notifications SET status='failed',failure_code='region-consent-changed',payload='{}'::jsonb
        WHERE installation_id IN (SELECT installation_id FROM parent) AND status IN ('pending','retrying')
        AND (payload->'regionConsent' IS DISTINCT FROM $${payloadIndex}::jsonb->'regionConsent'
          OR payload->'country' IS DISTINCT FROM $${payloadIndex}::jsonb->'country'
          OR payload->'region' IS DISTINCT FROM $${payloadIndex}::jsonb->'region')
      ), notification AS (
        INSERT INTO email_notifications(installation_id,event_type,payload) SELECT installation_id,'registration',$${payloadIndex}::jsonb FROM parent ON CONFLICT(installation_id,event_type) DO NOTHING
      ) SELECT installation_id FROM parent`,params);
      return rows.length===1;
    },
    async update(p,token,event) {
      const params=[p.installationId,hash(token),p.malguardVersion];
      let tail='SELECT installation_id FROM parent';
      if(event==='engine-status') {
        const cap=await capabilities(p); params.push(...cap.values);
        tail=`INSERT INTO installation_capabilities(installation_id,${cap.fields.join(',')}) SELECT installation_id,${cap.values.map((_,i)=>'$'+(i+4)).join(',')} FROM parent ON CONFLICT(installation_id) DO UPDATE SET ${cap.fields.map(n=>n+'=EXCLUDED.'+n).join(',')},updated_at=now() RETURNING installation_id`;
      }
      const rows=await lockedQuery(p.installationId, `WITH parent AS (UPDATE installations SET malguard_version=$3,updated_at=now() WHERE installation_id=$1::uuid AND credential_hash=$2 AND diagnostics_consent RETURNING installation_id) ${tail}`,params);
      return rows.length===1;
    },
    async unregister(id,token) {
      // Lock/delete the parent; cascading deletion removes capabilities and queued email.
      const rows=await lockedQuery(id, `WITH removed AS (
        DELETE FROM installations WHERE installation_id=$1::uuid AND credential_hash=$2 RETURNING installation_id
      ), tombstone AS (
        INSERT INTO telemetry_deletions(installation_id) SELECT $1::uuid
        WHERE EXISTS(SELECT 1 FROM removed) OR NOT EXISTS(SELECT 1 FROM installations WHERE installation_id=$1::uuid)
        ON CONFLICT(installation_id) DO UPDATE SET expires_at=now()+interval '30 days' RETURNING installation_id
      ) SELECT installation_id FROM tombstone`,[id,hash(token)]);
      return rows.length===1;
    },
    async list(offset=0) {
      // No credential hash reaches API or HTML.
      return query(`SELECT installation_id,${Object.values(COLUMNS).join(',')},created_at,updated_at,last_health_check_at FROM installations ORDER BY created_at DESC LIMIT 100 OFFSET $1`,[offset]);
    },
    async detail(id) {
      const rows=await query(`SELECT i.installation_id,${Object.values(COLUMNS).map(c=>'i.'+c).join(',')},i.created_at,i.updated_at,i.last_health_check_at,${Object.values(CAPS).map(c=>'c.'+c).join(',')},e.status AS email_status,e.attempt_count,e.failure_code FROM installations i LEFT JOIN installation_capabilities c USING(installation_id) LEFT JOIN email_notifications e USING(installation_id) WHERE i.installation_id=$1::uuid`,[id]);
      return rows[0]||null;
    },
    async summary() {
      return (await query("SELECT count(*)::integer AS total, count(*) FILTER(WHERE created_at>=date_trunc('day',now()))::integer AS new_today_utc, count(*) FILTER(WHERE updated_at>now()-interval '30 days')::integer AS active_30_days FROM installations",[]))[0];
    },
    async distributions() {
      const columns=['malguard_version','windows_version','device_manufacturer','device_model','cpu_model','ram_bytes','gpu_model','architecture','country','region'];
      return query(columns.map(c=>`(SELECT '${c}' AS field,COALESCE(${c}::text,'Unknown') AS value,count(*)::integer AS count FROM installations GROUP BY ${c} ORDER BY count(*) DESC LIMIT 50)`).join(' UNION ALL '),[]);
    },
    async claimEmail() {
      return (await query(`UPDATE email_notifications SET status='retrying',attempt_count=attempt_count+1,first_attempt_at=COALESCE(first_attempt_at,now()),last_attempt_at=now()
        WHERE id=(SELECT id FROM email_notifications WHERE (status='pending' OR (status='retrying' AND last_attempt_at<now()-interval '2 minutes')) AND attempt_count<5 AND (first_attempt_at IS NULL OR first_attempt_at>now()-interval '23 hours') ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED)
        RETURNING id,installation_id,payload,attempt_count`,[]))[0]||null;
    },
    async finishEmail(id,ok) { await query("UPDATE email_notifications SET status=CASE WHEN $2 THEN 'sent' WHEN attempt_count>=5 THEN 'failed' ELSE 'retrying' END,sent_at=CASE WHEN $2 THEN now() ELSE NULL END,failure_code=CASE WHEN $2 THEN NULL ELSE 'provider-unavailable' END WHERE id=$1::uuid",[id,ok]); },
    async emailExists(id) { return (await query('SELECT 1 FROM email_notifications WHERE id=$1::uuid',[id])).length===1; },
    async retention() {
      await query("DELETE FROM installations WHERE updated_at<now()-interval '90 days'",[]);
      await query("DELETE FROM telemetry_deletions WHERE expires_at<now()",[]);
      await query("UPDATE email_notifications SET status='failed',failure_code='retry-window-expired' WHERE status IN ('pending','retrying') AND first_attempt_at<now()-interval '23 hours'",[]);
      // Keep minimal event state for active installations to prevent a replay sending another email.
      await query("UPDATE email_notifications SET payload='{}'::jsonb WHERE status IN ('sent','failed') AND created_at<now()-interval '7 days'",[]);
    }
  };
}
function databaseFromEnvironment() {
  if(!process.env.DATABASE_URL) throw new Error('database-unavailable');
  const {neon}=require('@neondatabase/serverless');
  const sql=neon(process.env.DATABASE_URL);
  return createDatabase(
    (query,params)=>sql.query(query,params,{fetchOptions:{signal:AbortSignal.timeout(5000)}}),
    async (id,query,params)=>(await sql.transaction([
      sql.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[id]),
      sql.query(query,params)
    ],{isolationLevel:'ReadCommitted',fetchOptions:{signal:AbortSignal.timeout(5000)}}))[1]
  );
}
module.exports={createDatabase,databaseFromEnvironment,COLUMNS,CAPS};
