'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { MultiEngineScanner } = require('../desktop-app/multi-engine/multi-engine-scanner.js');

function fixtureDir() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'malguard-me-test-'));
  for (const file of ['yr.exe','capa.exe','floss.exe','MpCmdRun.exe']) fs.writeFileSync(path.join(root, file), 'fixture');
  fs.writeFileSync(path.join(root, 'ENGINE-BUNDLE.json'), JSON.stringify({schemaVersion:'1.0.0'}));
  const rules = path.join(root, 'rules.yar');
  fs.writeFileSync(rules, 'rule fixture { condition: false }');
  return { root, rules };
}

function fakeSpawn(mode) {
  return exe => {
    const base = path.basename(exe).toLowerCase();
    if (base === 'yr.exe') {
      const rules = mode === 'clean' ? [] : [{identifier:'MG_HIGH_PROCESS_INJECTION_CLUSTER'}];
      return {status:0,stdout:JSON.stringify({path:'sample',rules})+'\n',stderr:''};
    }
    if (base === 'capa.exe') {
      const rules = mode === 'clean' ? {'read file':{meta:{namespace:'host-interaction/file/read'}}} : {
        'inject code':{meta:{namespace:'host-interaction/process/inject'}},
        'communicate c2':{meta:{namespace:'c2/http'}},
      };
      return {status:0,stdout:JSON.stringify({rules}),stderr:''};
    }
    if (base === 'floss.exe') {
      const strings = mode === 'clean'
        ? {static_strings:[{string:'ScriptHookV'}]}
        : {decoded_strings:[{string:'Login Data'},{string:'powershell'},{string:'https://example.invalid'}]};
      return {status:0,stdout:JSON.stringify({strings}),stderr:''};
    }
    if (base === 'mpcmdrun.exe') {
      if (mode === 'defender-bad') return {status:2,stdout:'Threat : Trojan:Win32/SyntheticTest',stderr:''};
      return {status:0,stdout:'Scan finished.',stderr:''};
    }
    return {status:1,stdout:'',stderr:'unknown'};
  };
}

const f=fixtureDir();
try {
  const suspicious = new MultiEngineScanner({
    binaryRoot:f.root,
    rulesPath:f.rules,
    platform:'win32',
    defenderPath:path.join(f.root,'MpCmdRun.exe'),
    spawnSync:fakeSpawn('suspicious'),
  }).scanBuffer('sample.asi',Buffer.from('MZ synthetic fixture'),{mode:'pro'});
  assert.equal(suspicious.coverage.complete,true);
  assert.equal(suspicious.coverage.requiredForSafe,true);
  assert.equal(suspicious.engines.yaraX.status,'complete');
  assert.equal(suspicious.engines.capa.status,'complete');
  assert.equal(suspicious.engines.floss.status,'complete');
  assert.equal(suspicious.engines.defender.status,'complete');
  assert.equal(suspicious.verdict,'suspicious');
  assert.equal(suspicious.engines.floss.rawStringsExposed,false);

  const clean = new MultiEngineScanner({
    binaryRoot:f.root,
    rulesPath:f.rules,
    platform:'win32',
    defenderPath:path.join(f.root,'MpCmdRun.exe'),
    spawnSync:fakeSpawn('clean'),
  }).scanBuffer('sample.dll',Buffer.from('MZ clean fixture'),{mode:'standard'});
  assert.equal(clean.verdict,'safe');
  assert.equal(clean.coverage.complete,true);

  const detected = new MultiEngineScanner({
    binaryRoot:f.root,
    rulesPath:f.rules,
    platform:'win32',
    defenderPath:path.join(f.root,'MpCmdRun.exe'),
    spawnSync:fakeSpawn('defender-bad'),
  }).scanBuffer('sample.dll',Buffer.from('MZ defender fixture'),{mode:'pro'});
  assert.equal(detected.verdict,'malicious');
  assert.equal(detected.engines.defender.detected,true);

  console.log('✓ Multi-engine scanner: independent YARA-X/capa/FLOSS/Defender normalization, clean/suspicious/malicious policy PASS');
} finally {
  fs.rmSync(f.root,{recursive:true,force:true});
}
