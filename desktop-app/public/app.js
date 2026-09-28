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

const VERDICT_COPY={
 safe:{label:'No detection',tone:'inconclusive',title:'No safety approval',message:'No detected static indicator is not proof of safety.'},
 suspicious:{label:'Review recommended',tone:'warning',title:'Suspicious indicators detected',message:'Review the evidence before using this file. This scan has not quarantined or blocked it.'},
 malicious:{label:'Threat detected',tone:'danger',title:'Malicious evidence detected',message:'Do not run this file. This scan has not quarantined or blocked it.'},
 inconclusive:{label:'Unclear',tone:'inconclusive',title:'No safety verdict',message:'The analysis did not establish that this file is safe. Do not treat it as approved.'},
};
let activeScanId=null;
function currentModel(){return 'unified'}
function cloudFallbackEnabled(){return false}
function aiEvidenceEnabled(){return false}
function updateModelUi(){
 $('modelFlowTitle').textContent='Static analysis and reputation';
 resetCustomerResult('Ready for local analysis without executing the file.');
}

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
function standardSupportsFile(name){return /\.(asi|dll|lua|cs|zip)$/i.test(name||'')}
function scanFailureMessage(code){
 if(code==='UPLOAD_NAME_INVALID')return 'The file name cannot be processed. Rename it and try again.';
 if(code==='UPLOAD_EMPTY')return 'The selected file is empty. Choose a different file.';
 if(code==='UPLOAD_TOO_LARGE')return 'The file is larger than 64 MB. Choose a smaller file.';
 if(code==='LOCAL_UPLOAD_ORIGIN_REJECTED')return 'Open GTA Guard from its Desktop shortcut and try again.';
 if(code==='SCAN_CANCELLED')return 'Scan cancelled. No safety verdict was issued.';
 if(code==='TOO_MANY_LOCAL_SCANS')return 'The scanner is busy. Wait for active scans to finish.';
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
function renderCustomerResult(session){
 const result=session&&session.finalResult;
 const box=$('modelFinal');
 box.replaceChildren();
 if(!result){box.textContent=session&&session.state==='cancelling'?'Stopping analysis and cleaning up…':'Analysis in progress…';return;}
 const copy=VERDICT_COPY[result.verdict]||VERDICT_COPY.inconclusive;
 box.className=`scan-result result-${copy.tone}`;
 const title=document.createElement('strong');title.textContent=copy.title;
 const message=document.createElement('p');message.textContent=copy.message;
 const limitations=document.createElement('p');limitations.textContent='Static analysis only. No sample execution or external file upload. '+(result.limitations||[]).join(' · ');
 const intel=document.createElement('p');
 const reputation=result.localResult&&result.localResult.threatIntel;
 intel.textContent='MalwareBazaar: '+(reputation&&reputation.status||'not_checked')+(reputation&&reputation.reason?' ('+reputation.reason+')':'');
 box.append(title,message,intel,limitations);
 $('modelDiagnostics').hidden=false;
 out('modelDiagnosticsOut',result);
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
 activeScanId=id;
 $('cancelScan').disabled=false;
 renderPipeline(started.session);
 for(let i=0;i<600;i++){
   await new Promise(r=>setTimeout(r,250));
   const d=await api(`/api/model-scan/status?id=${encodeURIComponent(id)}`);
   renderPipeline(d.session);
   if(['completed','failed','cancelled'].includes(d.session.state)) return d.session;
 }
 await api('/api/model-scan/cancel','POST',{id});
 throw new Error('SCAN_POLL_TIMEOUT');
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
 if(!standardSupportsFile(file?file.name:p)){
   setScanSummary('GTA Guard scans supported GTA .asi/.dll plugins, .lua/.cs scripts and .zip mod packages. This file type is outside scanner coverage, so no scan was run.','unsupported');
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
   }else if(session.state==='cancelled'){
     setScanSummary('Scan cancelled. No safety verdict was issued.','inconclusive');
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
   $('cancelScan').disabled=true;
   activeScanId=null;
 }
};
$('cancelScan').onclick=async()=>{
 if(!activeScanId)return;
 $('cancelScan').disabled=true;
 try{const d=await api('/api/model-scan/cancel','POST',{id:activeScanId});if(!d.ok)throw new Error(d.code);setScanSummary('Stopping analysis; waiting for active reads and temporary file cleanup…','neutral');}
 catch(e){$('cancelScan').disabled=false;setScanSummary('Cancellation could not be confirmed. The scan may still be running.','error');}
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
