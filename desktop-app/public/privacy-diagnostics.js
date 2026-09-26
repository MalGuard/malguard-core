'use strict';
(() => {
  const el=id=>document.getElementById(id);
  async function request(route, body) {
    const response=await fetch(`/api/diagnostics/${route}`,{method:body?'POST':'GET',headers:{'x-malguard-privacy':'1',...(body?{'content-type':'application/json'}:{})},body:body?JSON.stringify(body):undefined});
    const result=await response.json();
    if (!response.ok) throw new Error(result.code || 'Privacy settings unavailable');
    return result;
  }
  async function refresh() {
    const r=await request('status'), d=r.diagnostics;
    el('privacyFirstLaunch').hidden=!!d.consentUpdatedAt;
    el('diagnosticsEnabled').checked=d.enabled;
    el('regionEnabled').checked=d.shareRegion;
    el('regionCountry').value=d.country||''; el('regionName').value=d.region||'';
    el('privacyState').textContent=`Sharing: ${d.enabled?'On':'Off'}\nAnonymous installation ID: ${d.installationId}\nLast successful upload: ${d.lastUploadAt||'Never'}\nStatus: ${d.deletionPending?'Deletion pending — retry when online':r.status}`;
  }
  const run=fn=>async()=>{try{await fn();await refresh();}catch(_){el('privacyState').textContent='Could not save or retrieve privacy settings. Scanning remains available; retry this action.';}};
  el('privacyAllow').onclick=run(()=>request('consent',{enabled:true,shareRegion:false}));
  el('privacyReject').onclick=run(()=>request('consent',{enabled:false,shareRegion:false}));
  el('privacySave').onclick=run(()=>request('consent',{enabled:el('diagnosticsEnabled').checked,shareRegion:el('regionEnabled').checked,country:el('regionCountry').value.toUpperCase()||null,region:el('regionName').value||null}));
  el('privacyDelete').onclick=run(()=>request('delete',{}));
  el('privacyPreview').onclick=run(async()=>{const r=await request('preview');el('privacyPayload').textContent=JSON.stringify(r.payload,null,2);});
  run(refresh)();
})();
