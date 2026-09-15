'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const ROOT = path.resolve(__dirname, '..');
function load(c,n){ vm.runInContext(fs.readFileSync(path.join(ROOT,n),'utf8'),c,{filename:n}); }
function context(){ const c={console,window:null}; c.window=c; vm.createContext(c); load(c,'malguard-contract.js'); c.MalGuardEngine={version:'2.2.2'}; c.MultiLayerSecurity={version:'1.0.0',analyze:r=>({finalVerdict:r.verdict,gates:[]})}; c.GtaModDetector={version:'1.0.0',analyze:async()=>({route:'ENGINE',modType:'plugin'})}; c.ArchiveInspector={version:'1.1.0'}; c.ArchiveEntryReader={version:'1.1.1'}; c.ScriptAnalyzer={version:'1.0.0'}; load(c,'app.js'); return c; }
(async()=>{
  // FREE must not turn degraded rules coverage into SAFE.
  let c=context();
  c.scanFile=async()=>({verdict:'safe',rulesStatus:'fallback',score:100,hash:'0'.repeat(64),engineVersion:'2.2.2'});
  let r=await c.scanFileWithMode({name:'x.asi',size:1},'free');
  assert.equal(r.finalVerdict,'inconclusive');
  assert.equal(r.hardeningError,'degraded_rules_coverage');

  // PRO must not fall open to Engine SAFE when MultiLayer is absent.
  c=context();
  c.GtaModDetector={version:'1.0.0',analyze:async()=>({route:'ENGINE',modType:'plugin'})};
  c.MultiLayerSecurity=undefined;
  c.scanFile=async()=>({verdict:'safe',rulesStatus:'official',score:100,hash:'0'.repeat(64),engineVersion:'2.2.2'});
  r=await c.scanFileWithMode({name:'x.asi',size:1},'pro');
  assert.equal(r.finalVerdict,'inconclusive');
  assert.equal(r.hardeningError,'multilayer_unavailable');

  // Stronger base verdicts are preserved if the secondary layer disappears.
  c.scanFile=async()=>({verdict:'malicious',rulesStatus:'official',score:0,hash:'0'.repeat(64),engineVersion:'2.2.2'});
  r=await c.scanFileWithMode({name:'x.asi',size:1},'pro');
  assert.equal(r.finalVerdict,'malicious');

  console.log('✓ Final security audit invariants: degraded rules and missing Pro layer fail closed');
})().catch(e=>{console.error(e.stack||e);process.exit(1);});
