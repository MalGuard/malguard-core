'use strict';
const assert = require('assert');
const contract = require('../desktop-guard/guard-contract.js');
const policy = require('../desktop-guard/containment-policy.js');
const report = require('../desktop-guard/incident-report.js');
const { NativeGuardAdapter } = require('../desktop-guard/native-adapter.js');

assert.equal(contract.version, '0.2.0');
assert.deepEqual(contract.validateGuardEvent({type:'file_created',path:'C:/Game/mods/test.lua',timestamp:1,size:12}), {ok:true});
assert.equal(contract.validateGuardEvent({type:'file_created',path:'',timestamp:1}).ok, false);
assert.equal(policy.decideContainment({verdict:'SAFE',reasons:[]}).action, 'release');
assert.equal(policy.decideContainment({verdict:'SUSPICIOUS',reasons:['x']}).action, 'quarantine');
assert.equal(policy.decideContainment({verdict:'MALICIOUS',reasons:['x']}).action, 'block_and_quarantine');
assert.equal(policy.decideContainment({verdict:'INCONCLUSIVE',reasons:[]}).action, 'hold');
assert.equal(policy.decideContainment({verdict:'BROKEN'}).failClosed, true);
const incident = report.createIncidentReport({modName:'Example',responsibleFile:'mod.lua',verdict:'MALICIOUS',reason:'rule',action:'block_and_quarantine',timestamp:2});
assert.equal(incident.modName, 'Example');
assert.equal(incident.responsibleFile, 'mod.lua');
assert.equal(incident.schemaVersion, '1.0.0');

(async()=>{
  const adapter = new NativeGuardAdapter();
  let threw = false;
  try { await adapter.startWatching(); } catch (e) { threw = e && e.code === 'NATIVE_GUARD_NOT_IMPLEMENTED'; }
  assert.equal(threw, true, 'native adapter must fail explicitly rather than fake monitoring');
  console.log('✓ Desktop Guard v0.1 contract: fail-closed containment/attribution/native boundary PASS');
})().catch(err=>{ console.error(err); process.exit(1); });
