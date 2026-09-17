'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { canonicalize } = require('../desktop-app/update/secure-update.js');
const {
  MalGuardMicroVMBackend,
  verifyMicroVmImage,
  validateMicroVmEvidence,
} = require('../desktop-app/sandbox/malguard-microvm-backend.js');

(async () => {
  const root = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'malguard-microvm-test-'));
  try {
    const imagePath = path.join(root, 'malguard-microvm-base.vhdx');
    const imageBytes = Buffer.from('harmless synthetic MalGuard MicroVM image fixture\n');
    await fs.promises.writeFile(imagePath, imageBytes);
    const imageSha256 = crypto.createHash('sha256').update(imageBytes).digest('hex');
    const manifest = {
      schemaVersion: '1.0.0',
      product: 'MalGuard MicroVM',
      imageId: 'malguard-microvm-base',
      version: '0.1.0',
      image: { sha256: imageSha256, size: imageBytes.length },
    };
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
    const signature = crypto.sign(null, Buffer.from(canonicalize(manifest), 'utf8'), privateKey).toString('base64');

    const trust = verifyMicroVmImage({ imagePath, manifest, signature, publicKeyPem });
    assert.equal(trust.ok, true);
    assert.equal(trust.sha256, imageSha256);

    const evidence = {
      schemaVersion: '1.0.0',
      sessionId: '11111111-1111-4111-8111-111111111111',
      imageSha256,
      vmBooted: true,
      guestAgentAuthenticated: true,
      networkDisabled: true,
      hostInputReadOnly: true,
      disposableOverlay: true,
      hostClipboardDisabled: true,
      sampleAttempted: true,
      sampleStarted: true,
    };
    assert.equal(validateMicroVmEvidence(evidence, {
      sessionId: evidence.sessionId,
      imageSha256,
      requireSampleExecution: true,
    }).ok, true);

    assert.equal(validateMicroVmEvidence({ ...evidence, sampleStarted: false }, {
      sessionId: evidence.sessionId,
      imageSha256,
      requireSampleExecution: true,
    }).code, 'MICROVM_SAMPLE_EXECUTION_NOT_STARTED');
    assert.equal(validateMicroVmEvidence({ ...evidence, networkDisabled: false }, {
      sessionId: evidence.sessionId,
      imageSha256,
      requireSampleExecution: true,
    }).ok, false);

    const tampered = Buffer.from(imageBytes);
    tampered[0] ^= 0x01;
    await fs.promises.writeFile(imagePath, tampered);
    assert.throws(() => verifyMicroVmImage({ imagePath, manifest, signature, publicKeyPem }), /sha256 mismatch/);
    await fs.promises.writeFile(imagePath, imageBytes);

    const manifestPath = `${imagePath}.manifest.json`;
    const signaturePath = `${imagePath}.manifest.sig`;
    await fs.promises.writeFile(manifestPath, JSON.stringify(manifest, null, 2) + '\n');
    await fs.promises.writeFile(signaturePath, signature + '\n');
    const backend = new MalGuardMicroVMBackend({
      launcherPath: path.join(root, 'missing-MalGuardMicroVMHost.exe'),
      imagePath,
      imageManifestPath: manifestPath,
      imageSignaturePath: signaturePath,
      imagePublicKeyPem: publicKeyPem,
      sessionRoot: path.join(root, 'sessions'),
    });
    const caps = await backend.capabilities();
    assert.equal(caps.backend, 'malguard-microvm');
    assert.equal(caps.imageTrusted, true);
    assert.equal(caps.releaseGrade, false);
    assert(caps.blockers.includes(process.platform === 'win32' ? 'malguard_microvm_launcher_missing' : 'microvm_windows_host_required'));

    const samplePath = path.join(root, 'synthetic.cmd');
    await fs.promises.writeFile(samplePath, '@echo off\r\nexit /b 0\r\n');
    const denied = await backend.analyze(samplePath, null);
    assert.equal(denied.ok, false);
    assert.equal(denied.verdict, 'inconclusive');
    assert.equal(denied.code, 'MALGUARD_MICROVM_UNAVAILABLE');

    console.log('✓ MalGuard MicroVM foundation: signed image trust, execution evidence and fail-closed launch gate PASS');
  } finally {
    await fs.promises.rm(root, { recursive: true, force: true });
  }
})().catch(error => {
  console.error(error.stack || error);
  process.exit(1);
});
