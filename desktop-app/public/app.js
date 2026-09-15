'use strict';
const $=id=>document.getElementById(id);
async function api(path, method='GET', body){
 const res=await fetch(path,{method,headers:body?{'content-type':'application/json'}:{},body:body?JSON.stringify(body):undefined});
 const data=await res.json();
 if(!res.ok && !data) throw new Error(`HTTP ${res.status}`);
 return data;
}
function out(id,data){$(id).textContent=JSON.stringify(data,null,2)}
async function status(){try{const s=await api('/api/status');$('status').textContent=s.watching?'Guard active':'Guard idle';out('guardOut',s)}catch(e){$('status').textContent='Offline'}}
document.querySelectorAll('.tab').forEach(b=>b.onclick=()=>{document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));document.querySelectorAll('.panel').forEach(x=>x.classList.remove('active'));b.classList.add('active');$(b.dataset.tab).classList.add('active')});

const MODEL_HINTS={
 standard:'Standard: local scan only.',
 plus:'Plus: deep staged analysis; suspicious or inconclusive files are routed to Sandbox automatically.',
 pro:'Pro: direct Sandbox analysis. No normal Standard/Plus scan is run before the Sandbox.',
};
function currentModel(){return $('scanModel').value}
function updateModelUi(){
 const model=currentModel();
 $('modelHint').textContent=MODEL_HINTS[model]||'';
 $('modelFlow').hidden=model==='standard';
 $('modelFlowTitle').textContent=model==='pro'?'Pro Sandbox flow':'Plus analysis flow';
 if(model!=='standard'){
   $('modelSteps').innerHTML='';
   $('modelFinal').textContent=model==='pro'?'Waiting for direct Sandbox analysis.':'Waiting for Plus scan.';
 }
}
$('scanModel').onchange=updateModelUi;
updateModelUi();

function renderPipeline(session){
 const list=$('modelSteps'); list.innerHTML='';
 for(const e of session.events||[]){
   const row=document.createElement('div'); row.className=`pipeline-step step-${e.status}`;
   const dot=document.createElement('span'); dot.className='pipeline-dot'; dot.textContent=e.status==='completed'?'✓':e.status==='failed'?'×':e.status==='warning'?'!':e.status==='blocked'?'!':'•';
   const text=document.createElement('div');
   const title=document.createElement('div'); title.className='pipeline-message'; title.textContent=e.message;
   const meta=document.createElement('div'); meta.className='muted'; meta.textContent=`${e.phase} · ${e.status}`;
   text.append(title,meta); row.append(dot,text); list.append(row);
 }
 if(session.finalResult){$('modelFinal').textContent=JSON.stringify(session.finalResult,null,2)}
}
async function runModelScan(path,model){
 $('modelSteps').innerHTML=''; $('modelFinal').textContent='Waiting for final verdict…';
 const started=await api('/api/model-scan/start','POST',{path,model});
 const id=started.session.id;
 if(model!=='standard') renderPipeline(started.session);
 for(let i=0;i<600;i++){
   await new Promise(r=>setTimeout(r,250));
   const d=await api(`/api/model-scan/status?id=${encodeURIComponent(id)}`);
   if(model!=='standard') renderPipeline(d.session);
   if(d.session.state==='completed'||d.session.state==='failed') return d.session;
 }
 throw new Error('Model scan status polling timed out');
}

$('scanBtn').onclick=async()=>{
 const p=$('scanPath').value;
 const model=currentModel();
 try{
   const session=await runModelScan(p,model);
   out('scanOut',{ok:true,model,finalResult:session.finalResult});
 }catch(e){
   out('scanOut',{ok:false,model,code:'MODEL_SCAN_UI_ERROR',message:e.message});
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

function renderFinalSandboxAcceptance(report){
 const releaseReady=!!(report&&report.releaseReady===true);
 const backend=report&&report.windowsSandbox?report.windowsSandbox:null;
 const available=!!(backend&&backend.available===true);
 const summary=$('finalSandboxSummary');
 if(releaseReady){
   summary.textContent='CERTIFIED — real Windows Sandbox containment and isolation acceptance PASS.';
 }else if(available){
   summary.textContent='PENDING — Windows Sandbox is present, but one or more final acceptance gates did not pass.';
 }else{
   summary.textContent='PENDING — Windows Sandbox is not available on this host. No certification has been claimed.';
 }
 out('finalSandboxOut',report);
}
$('finalSandboxTest').onclick=async()=>{
 const button=$('finalSandboxTest');
 button.disabled=true;
 $('finalSandboxSummary').textContent='Running synthetic-only final Sandbox acceptance…';
 $('finalSandboxOut').textContent='Running…';
 try{
   const report=await api('/api/sandbox/self-test','POST',{});
   renderFinalSandboxAcceptance(report);
 }catch(e){
   $('finalSandboxSummary').textContent='FAIL — final Sandbox acceptance request could not complete.';
   out('finalSandboxOut',{ok:false,code:'FINAL_SANDBOX_ACCEPTANCE_UI_ERROR',message:e.message});
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
status();
