'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Readable, Transform } = require('stream');
const { pipeline } = require('stream/promises');

const appRoot = path.resolve(__dirname, '..');
const aiRoot = path.join(appRoot, 'offline-ai');
const lock = JSON.parse(fs.readFileSync(path.join(aiRoot, 'model-lock.json'), 'utf8'));
const dist = path.join(aiRoot, 'dist');

if (
  lock.schemaVersion !== '1.0.0' ||
  lock.repository !== 'onnx-community/Qwen2.5-0.5B-Instruct' ||
  !/^[a-f0-9]{40}$/.test(lock.commit) ||
  lock.dtype !== 'q4' ||
  !/^[a-f0-9]{64}$/.test(lock.modelSha256)
) {
  throw new Error('Invalid offline AI model lock');
}

function ensureFile(file) {
  if (!fs.existsSync(file) || !fs.statSync(file).isFile() || fs.statSync(file).size <= 0) {
    throw new Error('Missing required file: ' + file);
  }
}

function copyVendor() {
  const packageRoot = path.join(aiRoot, 'node_modules', '@huggingface', 'transformers', 'dist');
  const vendor = path.join(dist, 'vendor');
  fs.mkdirSync(vendor, { recursive: true });
  for (const name of [
    'transformers.web.min.js',
    'ort-wasm-simd-threaded.jsep.mjs',
    'ort-wasm-simd-threaded.jsep.wasm'
  ]) {
    const from = path.join(packageRoot, name);
    ensureFile(from);
    fs.copyFileSync(from, path.join(vendor, name));
  }
}

async function download(rel, target) {
  const encoded = rel.split('/').map(encodeURIComponent).join('/');
  const url = 'https://huggingface.co/' + lock.repository + '/resolve/' + lock.commit + '/' + encoded + '?download=true';
  const response = await fetch(url, {
    redirect: 'follow',
    headers: { 'user-agent': 'MalGuard-Offline-App-Builder/1.0' }
  });
  if (!response.ok || !response.body) {
    throw new Error('Model download failed for ' + rel + ': HTTP ' + response.status);
  }

  fs.mkdirSync(path.dirname(target), { recursive: true });
  const temp = target + '.part';
  fs.rmSync(temp, { force: true });

  const hash = crypto.createHash('sha256');
  let size = 0;
  const meter = new Transform({
    transform(chunk, _encoding, callback) {
      size += chunk.length;
      hash.update(chunk);
      callback(null, chunk);
    }
  });

  await pipeline(Readable.fromWeb(response.body), meter, fs.createWriteStream(temp));
  fs.renameSync(temp, target);
  return { size, sha256: hash.digest('hex') };
}

async function main() {
  fs.rmSync(dist, { recursive: true, force: true });
  fs.mkdirSync(dist, { recursive: true });
  copyVendor();

  const modelRoot = path.join(dist, 'models', lock.localModelId);
  const manifest = {
    schemaVersion: '1.0.0',
    repository: lock.repository,
    commit: lock.commit,
    localModelId: lock.localModelId,
    dtype: lock.dtype,
    transformersVersion: lock.transformersVersion,
    files: {}
  };

  for (const rel of lock.files) {
    const target = path.join(modelRoot, ...rel.split('/'));
    process.stdout.write('Downloading pinned offline model file: ' + rel + '\n');
    const meta = await download(rel, target);
    manifest.files[rel] = meta;

    if (rel === lock.modelFile) {
      if (meta.size !== lock.modelSize) {
        throw new Error('Offline model size mismatch: expected ' + lock.modelSize + ', got ' + meta.size);
      }
      if (meta.sha256 !== lock.modelSha256) {
        throw new Error('Offline model SHA-256 mismatch');
      }
    }
  }

  const config = JSON.parse(fs.readFileSync(path.join(modelRoot, 'config.json'), 'utf8'));
  if (config.model_type !== 'qwen2') throw new Error('Unexpected offline model type');

  fs.writeFileSync(
    path.join(dist, 'OFFLINE-AI-SOURCE.json'),
    JSON.stringify({ ...lock, resolvedFiles: manifest.files }, null, 2) + '\n'
  );

  ensureFile(path.join(dist, 'vendor', 'transformers.web.min.js'));
  ensureFile(path.join(dist, 'vendor', 'ort-wasm-simd-threaded.jsep.wasm'));
  ensureFile(path.join(modelRoot, lock.modelFile));
  console.log('Fully offline MalGuard AI runtime prepared.');
}

main().catch(error => {
  console.error(error && error.stack ? error.stack : error);
  process.exit(1);
});
