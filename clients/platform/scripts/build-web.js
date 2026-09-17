'use strict';

const fs = require('fs');
const path = require('path');

const HERE = path.resolve(__dirname, '..');
const ROOT = path.resolve(HERE, '..', '..');
const SRC = path.join(HERE, 'web-src');
const OUT = path.join(HERE, 'www');

const CORE_FILES = [
  'malguard-contract.js',
  'engine.js',
  'multilayer.js',
  'gta-mod-detector.js',
  'archive-inspector.js',
  'archive-entry-reader.js',
  'script-analyzer.js',
  'app.js',
  'scan-worker-client.js',
  'scan-worker.js',
  'rules.json',
];

function copyRegularFile(source, target) {
  const stat = fs.lstatSync(source);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error(`Refusing non-regular source file: ${source}`);
  }
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.copyFileSync(source, target);
}

fs.rmSync(OUT, { recursive: true, force: true });
fs.mkdirSync(OUT, { recursive: true });

for (const name of ['index.html', 'platform.js', 'styles.css']) {
  copyRegularFile(path.join(SRC, name), path.join(OUT, name));
}

for (const name of CORE_FILES) {
  copyRegularFile(path.join(ROOT, name), path.join(OUT, name));
}

const buildInfo = {
  schemaVersion: '1.0.0',
  product: 'MalGuard Platform Client',
  generatedAt: new Date().toISOString(),
  sourceCommit: process.env.GITHUB_SHA || process.env.MALGUARD_SOURCE_COMMIT || null,
  coreFiles: CORE_FILES,
};
fs.writeFileSync(path.join(OUT, 'build-info.json'), JSON.stringify(buildInfo, null, 2) + '\n', 'utf8');

console.log(`MalGuard platform web bundle created at ${path.relative(ROOT, OUT)}`);
console.log(`Core scanner files: ${CORE_FILES.length}`);
