'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { MultiEngineScanner } = require('../desktop-app/multi-engine/multi-engine-scanner.js');

if (process.platform !== 'win32') {
  console.log('✓ Live Windows multi-engine smoke: skipped on non-Windows host');
  process.exit(0);
}

const required = process.env.MALGUARD_TSH_LIVE_MULTI_ENGINE === '1';
const marker = path.join(__dirname,'..','desktop-app','multi-engine','bin','ENGINE-BUNDLE.json');
if (!fs.existsSync(marker)) {
  if (required) throw new Error('Pinned multi-engine bundle is required but missing');
  console.log('✓ Live Windows multi-engine smoke: bundle not staged, skipped');
  process.exit(0);
}

const sample = path.join(process.env.SystemRoot || 'C:\\Windows','System32','where.exe');
assert(fs.existsSync(sample),'benign Windows system PE fixture missing');
const bytes=fs.readFileSync(sample);
const result=new MultiEngineScanner().scanBuffer('where.exe',bytes,{mode:'pro'});

for(const name of ['yaraX','capa','floss']){
  assert.equal(result.engines[name].status,'complete',name+' must execute successfully against the benign Windows PE');
}
assert.equal(result.coverage.complete,true,'pinned PE static engine coverage must be complete');
assert(['complete','unavailable'].includes(result.engines.defender.status),'Defender must either complete or be explicitly unavailable');

console.log('✓ Live Windows multi-engine smoke: real pinned YARA-X/capa/FLOSS executed against a benign Windows PE');
