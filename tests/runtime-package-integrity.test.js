'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { verifyRuntimePackageIntegrity } = require('../desktop-app/integrity/runtime-integrity.js');

function sha256(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function writeSealedFixture(root) {
  fs.mkdirSync(path.join(root, 'desktop-app'), { recursive: true });
  fs.writeFileSync(path.join(root, 'DESKTOP-VERSION'), '1.2.3\n');
  fs.writeFileSync(path.join(root, 'desktop-app', 'server.js'), "console.log('fixture');\n");
  const manifest = {
    schemaVersion: '1.0.0',
    product: 'MalGuard Desktop',
    desktopVersion: '1.2.3',
    entrypoint: 'desktop-app/server.js',
    node: '>=20',
    fileCount: 4,
  };
  fs.writeFileSync(path.join(root, 'PACKAGE-MANIFEST.json'), JSON.stringify(manifest, null, 2) + '\n');
  const files = ['DESKTOP-VERSION', 'PACKAGE-MANIFEST.json', 'desktop-app/server.js'];
  const sums = files.sort().map(file => `${sha256(path.join(root, ...file.split('/')))}  ${file}`).join('\n') + '\n';
  fs.writeFileSync(path.join(root, 'SHA256SUMS.txt'), sums);
}

const dev = fs.mkdtempSync(path.join(os.tmpdir(), 'malguard-integrity-dev-'));
try {
  assert.deepEqual(verifyRuntimePackageIntegrity(dev), {
    ok: true,
    sealed: false,
    mode: 'development-unsealed',
    checkedFiles: 0,
  });
  assert.equal(verifyRuntimePackageIntegrity(dev, { requireSealed: true }).code, 'RUNTIME_INTEGRITY_SEAL_MISSING');
} finally {
  fs.rmSync(dev, { recursive: true, force: true });
}

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'malguard-integrity-'));
try {
  writeSealedFixture(root);
  const good = verifyRuntimePackageIntegrity(root);
  assert.equal(good.ok, true);
  assert.equal(good.sealed, true);
  assert.equal(good.checkedFiles, 3);

  fs.appendFileSync(path.join(root, 'desktop-app', 'server.js'), '// tampered\n');
  assert.equal(verifyRuntimePackageIntegrity(root).code, 'RUNTIME_INTEGRITY_HASH_MISMATCH');

  fs.rmSync(root, { recursive: true, force: true });
  fs.mkdirSync(root, { recursive: true });
  writeSealedFixture(root);
  fs.writeFileSync(path.join(root, 'unexpected.js'), 'unexpected');
  const injected = verifyRuntimePackageIntegrity(root);
  assert(['RUNTIME_INTEGRITY_FILE_COUNT_MISMATCH', 'RUNTIME_INTEGRITY_UNEXPECTED_FILE_SET'].includes(injected.code));

  fs.rmSync(path.join(root, 'SHA256SUMS.txt'));
  assert.equal(verifyRuntimePackageIntegrity(root).code, 'RUNTIME_INTEGRITY_SEAL_INCOMPLETE');
} finally {
  fs.rmSync(root, { recursive: true, force: true });
}

console.log('✓ Runtime package integrity: sealed package verification, tamper detection, extra-file rejection and fail-closed seal handling PASS');
