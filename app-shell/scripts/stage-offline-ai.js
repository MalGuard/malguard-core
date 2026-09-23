'use strict';

const fs = require('fs');
const path = require('path');

const appRoot = path.resolve(__dirname, '..');
const targetArg = process.argv[2];
if (!targetArg) throw new Error('Usage: node stage-offline-ai.js <www-directory>');

const target = path.resolve(targetArg);
const source = path.join(appRoot, 'offline-ai');
const dist = path.join(source, 'dist');

if (!fs.existsSync(path.join(target, 'OFFLINE-SOURCE.json'))) {
  throw new Error('Offline site must be prepared before staging AI: ' + target);
}
for (const rel of [
  'dist/OFFLINE-AI-SOURCE.json',
  'dist/vendor/transformers.web.min.js',
  'dist/vendor/ort-wasm-simd-threaded.jsep.mjs',
  'dist/vendor/ort-wasm-simd-threaded.jsep.wasm',
  'offline-ai-engine.mjs',
  'offline-malware-ai-bootstrap.js'
]) {
  const p = path.join(source, rel);
  if (!fs.existsSync(p) || !fs.statSync(p).isFile()) throw new Error('Offline AI asset missing: ' + rel);
}

const assetRoot = path.join(target, 'assets', 'offline-ai');
fs.mkdirSync(path.join(assetRoot, 'vendor'), { recursive: true });
fs.copyFileSync(path.join(source, 'offline-ai-engine.mjs'), path.join(assetRoot, 'offline-ai-engine.mjs'));
fs.copyFileSync(path.join(source, 'offline-malware-ai-bootstrap.js'), path.join(assetRoot, 'offline-malware-ai-bootstrap.js'));
fs.cpSync(path.join(dist, 'vendor'), path.join(assetRoot, 'vendor'), { recursive: true });
fs.cpSync(path.join(dist, 'models'), path.join(target, 'models'), { recursive: true });
fs.copyFileSync(path.join(dist, 'OFFLINE-AI-SOURCE.json'), path.join(target, 'OFFLINE-AI-SOURCE.json'));

const manifest = JSON.parse(fs.readFileSync(path.join(target, 'OFFLINE-AI-SOURCE.json'), 'utf8'));
const model = path.join(target, 'models', manifest.localModelId, manifest.modelFile);
if (!fs.existsSync(model) || fs.statSync(model).size !== manifest.modelSize) {
  throw new Error('Staged offline model is incomplete');
}

console.log('Offline AI staged into ' + target);
