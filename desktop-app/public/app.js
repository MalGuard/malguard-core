'use strict';
const $=id=>document.getElementById(id);
async function api(path, method='GET', body){
 const res=await fetch(path,{method,headers:body?{'content-type':'application/json'}:{},body:body?JSON.stringify(body):undefined});
 const data=await res.json();
 if(!res.ok && !data) throw new Error(`HTTP ${res.status}`);
 return data;
}
function out(id,data){$(id).textContent=JSON.stringify(data,null,2)}
async function status(){try{const s=await api('/api/status');$('status').textContent=`${s.watching?'Guard active':'Guard idle'} · ${s.version}`;const build=$('buildId');if(build)build.textContent=s.build?`Build ${s.build}`:'Build unavailable';out('guardOut',s)}catch(e){$('status').textContent='Offline';const build=$('buildId');if(build)build.textContent='Build unavailable'}}
document.querySelectorAll('.tab').forEach(b=>b.onclick=()=>{document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));document.querySelectorAll('.panel').forEach(x=>x.classList.remove('active'));b.classList.add('active');$(b.dataset.tab).classList.add('active')});

const MODEL_HINTS={
 standard:'Standard: local GTA plugin scan + synthetic GTA context. Optional metadata-only MalGuard AI analysis.',
 plus:'Plus: deep local analysis + synthetic GTA context + optional disposable isolated GTA simulation and MalGuard AI evidence analysis.',
 pro:'Pro: verified local behavioral analysis when possible + GTA simulation + optional isolated cloud simulation and MalGuard AI evidence analysis.',
};
const VERDICT_COPY={
 safe:{label:'Safe',tone:'safe',title:'No threat detected',message:'MalGuard completed the selected analysis and found no malicious behavior in the available evidence.'},
 suspicious:{label:'Review recommended',tone:'warning',title:'Suspicious activity detected',message:'MalGuard found behavior or indicators that deserve caution. Keep the file blocked unless you trust its source.'},
 malicious:{label:'Threat blocked',tone:'danger',title:'Malicious activity detected',message:'MalGuard detected malicious evidence. Keep the file quarantined and do not run it.'},
 inconclusive:{label:'Unclear',tone:'inconclusive',title:'No safety verdict',message:'The analysis did not establish whether this file is safe. Do not treat it as approved.'},
};
function currentModel(){return $('scanModel').value}
function cloudFallbackEnabled(){const box=$('cloudFallback');return currentModel()!=='standard'&&!!(box&&box.checked)}
function aiEvidenceEnabled(){const box=$('aiEvidence');return !!(box&&box.checked)}
function updateModelUi(){
 const model=currentModel();
 $('modelHint').textContent=MODEL_HINTS[model]||'';
 const cloudOption=$('cloudFallbackOption');if(cloudOption)cloudOption.hidden=model==='standard'; if(cloudOption&&model!=='standard'){const box=$('cloudFallback');if(box)box.checked=true;}
 $('modelFlow').hidden=false;
 $('modelFlowTitle').textContent=model==='pro'?'Pro secure analysis + GTA simulation':model==='plus'?'Plus deep analysis + GTA simulation':'Standard local analysis + GTA simulation';
 $('modelSteps').innerHTML='';
 resetCustomerResult(model==='pro'?'Ready for isolated behavioral analysis and GTA simulation.':model==='plus'?'Ready for deep analysis and GTA simulation.':'Ready for local analysis and GTA simulation.');
}
$('scanModel').onchange=updateModelUi;

function resetCustomerResult(text='Ready to scan.'){
 const box=$('modelFinal');
 if(!box)return;
 box.className='scan-result result-neutral';
 box.textContent=text;
 const diagnostics=$('modelDiagnostics');
 if(diagnostics)diagnostics.hidden=true;
}
function setScanSummary(text,tone='neutral'){
 const box=$('scanOut');
 box.className=`scan-summary result-${tone}`;
 box.setAttribute('role',tone==='error'?'alert':'status');
 box.replaceChildren();
 if(['error','danger','warning','unsupported','inconclusive'].includes(tone)){
   const title=document.createElement('strong');
   title.textContent={error:'Scan failed',danger:'Threat detected',warning:'Review this result',unsupported:'Unsupported file type',inconclusive:'No safety verdict'}[tone];
   box.append(title,document.createElement('br'));
 }
 box.append(document.createTextNode(text));
}
function standardSupportsFile(name){return /\.(asi|dll)$/i.test(name||'')}
function scanFailureMessage(code){
 if(code==='UPLOAD_NAME_INVALID')return 'The file name cannot be processed. Rename it and try again.';
 if(code==='UPLOAD_EMPTY')return 'The selected file is empty. Choose a different file.';
 if(code==='UPLOAD_TOO_LARGE')return 'The file is larger than 64 MB. Choose a smaller file.';
 if(code==='LOCAL_UPLOAD_ORIGIN_REJECTED')return 'Open GTA Guard from its Desktop shortcut and try again.';
 if(String(code||'').startsWith('ENTITLEMENT_'))return 'This protection level is unavailable. Select Standard for .asi or .dll files.';
 return 'The scan stopped before a reliable result was available. The file was not marked safe. Open Scan diagnostics for the error code.';
}
function friendlyPhase(event){
 const phase=event&&event.phase;
 const status=event&&event.status;
 if(phase==='prepare')return 'Preparing secure analysis';
 if(phase==='standard_scan')return status==='completed'?'Standard protection scan completed':'Running Standard protection scan';
 if(phase==='static_scan')return status==='completed'?'Deep static analysis completed':'Running deep static analysis';
 if(phase==='archive_analysis')return 'Archive inspection completed';
 if(phase==='script_analysis')return 'Script analysis completed';
 if(phase==='correlation')return 'Security signals correlated';
 if(phase==='threat_intelligence')return 'Threat-intelligence check completed';
 if(phase==='sandbox_decision')return status==='warning'?'Additional isolated analysis selected':'Sandbox decision completed';
 if(phase==='preflight')return status==='completed'?'File prepared for isolated analysis':status==='blocked'?'File could not be prepared safely':'Preparing file for isolated analysis';
 if(phase==='gta_simulation')return status==='completed'?'Synthetic GTA context completed':status==='blocked'?'GTA simulation context unavailable':'Building synthetic GTA context';
 if(phase==='gta_cloud_simulation')return status==='completed'?'Disposable isolated GTA simulation completed':status==='blocked'?'Isolated GTA simulation unavailable':'Running disposable isolated GTA simulation';
 if(phase==='ai_evidence')return status==='completed'?'MalGuard AI evidence analysis completed':status==='warning'?'MalGuard AI analysis not requested':status==='blocked'?'MalGuard AI analysis unavailable':'Running MalGuard AI evidence analysis';
 if(phase==='cloud_ephemeral_inspection')return status==='completed'?'Disposable Cloud Inspection completed':status==='blocked'?'Cloud Inspection unavailable':'Running disposable Cloud Inspection';
 if(phase==='sandbox_analysis'){
   if(status==='blocked')return 'Local behavioral Sandbox unavailable';
   if(status==='completed')return 'Isolated behavioral analysis completed';
   return 'Running isolated behavioral analysis';
 }
 if(phase==='final_verdict')return status==='failed'?'Analysis stopped safely':'Analysis result ready';
 return event&&event.message?event.message:'Security check';
}
function friendlyMeta(event){
 const status=event&&event.status;
 if(event&&event.phase==='ai_evidence'&&status==='warning')return 'Optional · not requested';
 if(event&&event.phase==='ai_evidence'&&status==='completed')return 'Metadata only · advisory';
 if(event&&event.phase==='gta_cloud_simulation'&&status==='completed')return 'Destroyed after job';
 if(status==='completed')return 'Completed';
 if(status==='running')return 'In progress';
 if(status==='blocked')return 'Protected';
 if(status==='warning')return 'Additional protection';
 if(status==='failed')return 'Stopped safely';
 return 'Queued';
}
function pluginDirectExecutionUnsupported(result){
 return !!(result&&result.pluginDirectExecutionUnsupported===true);
}
function sandboxSetupRequired(result){
 return !!(result&&!pluginDirectExecutionUnsupported(result)&&(
   result.completionState==='sandbox_unavailable_fail_closed'||
   (result.sandboxRequested===true&&result.sandboxCompleted===false&&result.completionState!=='preflight_failed_closed')
 ));
}
function renderCustomerResult(session){
 const result=session&&session.finalResult?session.finalResult:null;
 const box=$('modelFinal');
 box.innerHTML='';
 const diagnostics=$('modelDiagnostics');
 const diagnosticsOut=$('modelDiagnosticsOut');
 if(diagnostics&&diagnosticsOut&&session){
   diagnostics.hidden=false;
   diagnosticsOut.textContent=JSON.stringify(session,null,2);
 }
 if(!result){
   box.className='scan-result result-neutral';
   box.textContent='Analysis is still running securely.';
   return;
 }
 const setupRequired=sandboxSetupRequired(result);
 const preflightBlocked=result.completionState==='preflight_failed_closed';
 const pluginFallback=pluginDirectExecutionUnsupported(result);
 let copy=VERDICT_COPY[result.verdict]||VERDICT_COPY.inconclusive;
 if(pluginFallback&&result.verdict==='inconclusive'){
   copy=result.cloudInspectionCompleted===true
     ?{label:'Protected',tone:'inconclusive',title:'GTA plugin inspected without direct execution',message:'This ASI/DLL plugin cannot be launched safely as a standalone Windows program. MalGuard completed local fallback analysis and disposable Cloud Inspection, but did not claim a SAFE result without real plugin execution proof.'}
     :{label:'Protected',tone:'inconclusive',title:'GTA plugin inspected without direct execution',message:'This ASI/DLL plugin cannot be launched safely as a standalone Windows program. MalGuard completed non-executing fallback analysis and kept the result inconclusive instead of pretending the plugin was behaviorally tested.'};
 }else if(setupRequired){
   copy=result.cloudInspectionCompleted===true
     ?{label:'Protected',tone:'setup',title:'Cloud inspection completed',message:'The disposable cloud environment inspected the file and was destroyed after the job, but Windows behavioral execution was not proven on this PC. MalGuard therefore did not mark the file safe.'}
     :{label:'Protected',tone:'setup',title:'Secure Sandbox setup required',message:'MalGuard kept the file protected because isolated execution is not ready on this PC. The file was not executed outside the Sandbox.'};
 }else if(preflightBlocked){
   copy={label:'Protected',tone:'setup',title:'File kept protected',message:'MalGuard could not prepare this file for isolated execution safely, so it stopped before running it.'};
 }
 box.className=`scan-result result-${copy.tone}`;
 const header=document.createElement('div');header.className='result-header';
 const title=document.createElement('div');title.className='result-title';title.textContent=copy.title;
 const badge=document.createElement('span');badge.className='result-badge';badge.textContent=copy.label;
 header.append(title,badge);
 const message=document.createElement('p');message.className='result-message';message.textContent=copy.message;
 box.append(header,message);
 const ai=result.aiEvidence;
 if(ai&&ai.status==='completed'){
   const aiNote=document.createElement('p');
   aiNote.className='result-note';
   const risk=String(ai.risk||'unknown').toUpperCase();
   aiNote.textContent='MalGuard AI · '+risk+(ai.summary?' · '+ai.summary:'')+' AI advice is advisory and does not change the security verdict.';
   box.append(aiNote);
 }
 if(result.gtaCloudSimulationCompleted===true){
   const simNote=document.createElement('p');
   simNote.className='result-note';
   simNote.textContent='Disposable GTA simulation environment completed and was destroyed after the job. The plugin was staged but not executed in this simulation phase.';
   box.append(simNote);
 }
 if(setupRequired){
   const note=document.createElement('p');note.className='result-note';note.textContent=result.cloudInspectionCompleted===true?'Cloud Inspection is inspection-only and cannot replace verified Windows behavioral execution for a SAFE verdict.':'Plus and Pro stay fail-closed until this device passes a real local behavioral isolation check.';
   const actions=document.createElement('div');actions.className='result-actions';
   const check=document.createElement('button');check.type='button';check.textContent='Check Sandbox compatibility';
   check.onclick=()=>{const tab=document.querySelector('.tab[data-tab="engine"]');if(tab)tab.click();const button=$('finalSandboxTest');if(button)button.click();};
   const standard=document.createElement('button');standard.type='button';standard.className='button-secondary';standard.textContent='Run Standard scan instead';
   standard.onclick=()=>{$('scanModel').value='standard';updateModelUi();$('scanBtn').click();};
   actions.append(check,standard);box.append(note,actions);
 }
}
function renderPipeline(session){
 const list=$('modelSteps'); list.innerHTML='';
 for(const e of session.events||[]){
   const row=document.createElement('div'); row.className=`pipeline-step step-${e.status}`;
   const dot=document.createElement('span'); dot.className='pipeline-dot'; dot.textContent=e.status==='completed'?'✓':e.status==='running'?'•':e.status==='blocked'?'✓':e.status==='failed'?'×':'•';
   const text=document.createElement('div');
   const title=document.createElement('div'); title.className='pipeline-message'; title.textContent=friendlyPhase(e);
   const meta=document.createElement('div'); meta.className='muted'; meta.textContent=friendlyMeta(e);
   text.append(title,meta); row.append(dot,text); list.append(row);
 }
 renderCustomerResult(session);
}
async function runModelScan(path,model,file=null){
 const useCloud=cloudFallbackEnabled();
 const useAi=aiEvidenceEnabled();
 $('modelSteps').innerHTML=''; resetCustomerResult('Starting secure analysis…');
 let started;
 if(file){
   const response=await fetch(`/api/model-scan/upload?model=${encodeURIComponent(model)}&name=${encodeURIComponent(file.name)}&cloudFallback=${useCloud?'1':'0'}&aiEvidence=${useAi?'1':'0'}`,{
     method:'POST',headers:{'content-type':'application/octet-stream','x-malguard-local-upload':'1'},body:file,
   });
   started=await response.json();
   if(!response.ok)throw new Error(started.code||'LOCAL_FILE_UPLOAD_FAILED');
 }else{
   started=await api('/api/model-scan/start','POST',{path,model,cloudFallback:useCloud,aiEvidence:useAi});
 }
 if(!started.session)throw new Error(started.code||'SCAN_NOT_STARTED');
 const id=started.session.id;
 renderPipeline(started.session);
 for(let i=0;i<600;i++){
   await new Promise(r=>setTimeout(r,250));
   const d=await api(`/api/model-scan/status?id=${encodeURIComponent(id)}`);
   renderPipeline(d.session);
   if(d.session.state==='completed'||d.session.state==='failed') return d.session;
 }
 throw new Error('Model scan status polling timed out');
}

$('scanFile').onchange=()=>{if($('scanFile').files.length)$('scanPath').value='';};
$('scanPath').oninput=()=>{if($('scanPath').value.trim())$('scanFile').value='';};
$('scanBtn').onclick=async()=>{
 const file=$('scanFile').files[0]||null;
 const p=$('scanPath').value.trim().replace(/^"(.*)"$/,'$1');
 const model=currentModel();
 if(!file&&!p){
   setScanSummary('Choose a file from this PC to begin scanning.','neutral');
   return;
 }
 if(model==='standard'&&!standardSupportsFile(file?file.name:p)){
   setScanSummary('Standard scans .asi and .dll GTA mod files only. ZIP packages and scripts require Plus or Pro when available; PDF files are not supported. No scan was run.','unsupported');
   return;
 }
 if(file&&file.size>64*1024*1024){setScanSummary(scanFailureMessage('UPLOAD_TOO_LARGE'),'error');return;}
 $('scanBtn').disabled=true;
 $('modelDiagnostics').hidden=true;
 setScanSummary('MalGuard is scanning the file securely…','neutral');
 try{
   const session=await runModelScan(p,model,file);
   const result=session&&session.finalResult?session.finalResult:null;
   renderCustomerResult(session);
   if(session.state==='failed'){
     setScanSummary(scanFailureMessage(session.error&&session.error.code),'error');
     $('modelDiagnostics').hidden=false;
     out('modelDiagnosticsOut',{code:session.error&&session.error.code||'SCAN_FAILED',message:session.error&&session.error.message||null});
   }else if(pluginDirectExecutionUnsupported(result)){
     setScanSummary(result.cloudInspectionCompleted===true
       ?'GTA plugin inspected locally and in a disposable cloud environment. Direct plugin execution was not performed, so the result remains fail-closed.'
       :'GTA plugin inspected with non-executing fallback analysis. Direct plugin execution was not performed, so MalGuard did not claim a SAFE result.','inconclusive');
   }else if(sandboxSetupRequired(result)){
     setScanSummary(result&&result.cloudInspectionCompleted===true?'Cloud isolated analysis completed. Local behavioral execution was unavailable, so MalGuard preserved a fail-closed verdict.':'File kept protected. Local behavioral isolation was unavailable; MalGuard completed every available defensive fallback and did not mark the file safe.','setup');
   }else if(result&&result.completionState==='preflight_failed_closed'){
     setScanSummary('File kept protected because MalGuard could not prepare it safely for isolated execution.','setup');
   }else if(result&&result.verdict==='inconclusive'){
     setScanSummary(VERDICT_COPY.inconclusive.message,'inconclusive');
   }else{
     const copy=VERDICT_COPY[result&&result.verdict]||VERDICT_COPY.inconclusive;
     setScanSummary(`${copy.title}. ${copy.message}`,copy.tone);
   }
 }catch(e){
   setScanSummary(scanFailureMessage(e.message),'error');
   const diagnostics=$('modelDiagnostics');
   const diagnosticsOut=$('modelDiagnosticsOut');
   if(diagnostics&&diagnosticsOut){diagnostics.hidden=false;diagnosticsOut.textContent=JSON.stringify({code:'MODEL_SCAN_UI_ERROR',message:e.message},null,2);}
 }finally{
   $('scanBtn').disabled=false;
 }
};
async function loadThreatStatus(){out('threatOut',await api('/api/threat-intel/status'))}
$('threatStatus').onclick=loadThreatStatus;
$('saveThreatKey').onclick=async()=>{const authKey=$('abuseAuthKey').value.trim();if(!authKey){out('threatOut',{ok:false,code:'AUTH_KEY_REQUIRED'});return}const d=await api('/api/threat-intel/credential','POST',{authKey});$('abuseAuthKey').value='';out('threatOut',d);await loadThreatStatus()};
$('clearThreatKey').onclick=async()=>{const d=await api('/api/threat-intel/credential','DELETE');$('abuseAuthKey').value='';out('threatOut',d);await loadThreatStatus()};
$('startGuard').onclick=async()=>{out('guardOut',await api('/api/guard/start','POST',{}));await status()};
$('stopGuard').onclick=async()=>{out('guardOut',await api('/api/guard/stop','POST',{}));await status()};
$('enableGate').onclick=async()=>out('gateOut',await api('/api/access-gate/enable','POST',{}));
$('disableGate').onclick=async()=>out('gateOut',await api('/api/access-gate/disable','POST',{}));
$('gateStatus').onclick=async()=>out('gateOut',await api('/api/access-gate/status'));

function renderIsolationReadiness(report){
 const productReady=!!(report&&report.productReleaseReady===true);
 const runtimeReady=!!(report&&report.runtimeCapabilitiesReadyOnCurrentHost===true);
 const summary=$('finalSandboxSummary');
 summary.className=runtimeReady?'health-card health-ready':'health-card health-setup';
 if(runtimeReady){
   summary.textContent='Secure Sandbox is ready on this PC. Plus and Pro can run isolated behavioral analysis.';
 }else if(productReady){
   summary.textContent='MalGuard is installed correctly. Secure Sandbox needs setup or compatibility approval on this PC before Plus/Pro can execute files in isolation.';
 }else{
   summary.textContent='MalGuard completed the compatibility check, but this installation still needs attention before premium Sandbox analysis can run.';
 }
 const diagnostics=$('finalSandboxDiagnostics');
 if(diagnostics)diagnostics.hidden=false;
 out('finalSandboxOut',report);
}
$('finalSandboxTest').onclick=async()=>{
 const button=$('finalSandboxTest');
 button.disabled=true;
 $('finalSandboxSummary').className='health-card health-checking';
 $('finalSandboxSummary').textContent='Checking secure Sandbox compatibility on this PC…';
 try{
   const report=await api('/api/sandbox/readiness','POST',{});
   renderIsolationReadiness(report);
 }catch(e){
   $('finalSandboxSummary').className='health-card health-setup';
   $('finalSandboxSummary').textContent='Compatibility check could not finish. Premium Sandbox execution remains safely disabled until the check succeeds.';
   const diagnostics=$('finalSandboxDiagnostics');if(diagnostics)diagnostics.hidden=false;
   out('finalSandboxOut',{code:'ISOLATION_READINESS_UI_ERROR',message:e.message});
 }finally{
   button.disabled=false;
 }
};
$('selfTest').onclick=async()=>out('selfOut',await api('/api/self-test','POST',{}));
$('refreshQ').onclick=async()=>{const d=await api('/api/quarantine');const box=$('quarantine');box.innerHTML='';for(const q of d.entries||[]){const e=document.createElement('div');e.className='qitem';const t=document.createElement('div');t.textContent=`${q.responsibleFile||'file'} • ${q.verdict} • ${q.state}`;const p=document.createElement('div');p.className='muted';p.textContent=q.originalPath||'';e.append(t,p);if(q.state==='quarantined'){const b=document.createElement('button');b.textContent='Restore';b.onclick=async()=>{await api('/api/quarantine/restore','POST',{id:q.id});$('refreshQ').click()};e.append(b)}box.append(e)}};
async function loadSettings(){const d=await api('/api/settings');const x=d.settings||{};$('watchRoot').value=(x.watchRoots||[])[0]||'';$('quarantineRoot').value=x.quarantineRoot||'';$('stagingRoot').value=x.stagingRoot||'';out('settingsOut',d)}
$('loadSettings').onclick=loadSettings;
$('saveSettings').onclick=async()=>{const watch=$('watchRoot').value.trim();const d=await api('/api/settings','POST',{watchRoots:watch?[watch]:[],quarantineRoot:$('quarantineRoot').value,stagingRoot:$('stagingRoot').value});out('settingsOut',d);await status()};
$('refreshIncidents').onclick=async()=>out('incidentsOut',await api('/api/incidents'));
loadSettings().catch(e=>out('settingsOut',{ok:false,error:e.message}));
loadThreatStatus().catch(e=>out('threatOut',{ok:false,error:e.message}));
updateModelUi();
setScanSummary('Ready to scan.','neutral');
status();
