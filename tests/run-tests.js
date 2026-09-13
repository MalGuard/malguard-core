'use strict';
const { spawnSync } = require('child_process');
const path = require('path');

const tests = [
  'script-analyzer.test.js',
  'regression-corpus.test.js',
  'pe-fuzz.test.js',
  'web-worker.test.js',
  'build-validation.test.js',
 'mutation-sensitivity.test.js',
];

for (const test of tests) {
  const full = path.join(__dirname, test);
  const r = spawnSync(process.execPath, [full], { stdio: 'inherit' });
  if (r.status !== 0) process.exit(r.status || 1);
}
console.log('✓ MalGuard Web Worker milestone: all automated test suites PASS');
