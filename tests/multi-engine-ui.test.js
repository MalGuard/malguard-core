'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const root=path.resolve(__dirname,'..');
const js=fs.readFileSync(path.join(root,'desktop-app/public/app.js'),'utf8');
const html=fs.readFileSync(path.join(root,'desktop-app/public/index.html'),'utf8');

for(const name of ['YARA-X','capa','FLOSS','Microsoft Defender']){
  assert(js.includes(name)||html.includes(name),'UI must name real independent engine: '+name);
}
assert(js.includes("result.verdict==='inconclusive'"),'Sandbox setup UI must not override a conclusive Fusion verdict');
assert(js.includes('Deep Multi-Engine static verification completed'),'UI must explain successful static fallback when behavioral evidence is unavailable');
assert(js.includes('engine-results'),'UI must render per-engine results');
console.log('✓ Multi-engine UI: real engine disclosure, per-engine diagnostics and no stale Sandbox override PASS');
