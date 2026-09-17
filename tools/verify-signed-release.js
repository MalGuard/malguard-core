'use strict';

const fs = require('fs');
const path = require('path');
const { verifySignedRelease } = require('../desktop-app/update/release-trust.js');

function main() {
  const packageArg = process.argv[2];
  const manifestArg = process.argv[3];
  const signatureArg = process.argv[4];
  if (!packageArg || !manifestArg || !signatureArg) {
    throw new Error('usage: node tools/verify-signed-release.js <release-package> <manifest.json> <manifest.sig>');
  }

  const publicKeyPem = process.env.MALGUARD_RELEASE_PUBLIC_KEY_PEM;
  const trustedPublicKeySha256 = process.env.MALGUARD_RELEASE_PUBLIC_KEY_SHA256;
  const expectedSourceCommit = process.env.MALGUARD_EXPECTED_SOURCE_COMMIT;
  if (typeof publicKeyPem !== 'string' || !publicKeyPem.trim()) throw new Error('MALGUARD_RELEASE_PUBLIC_KEY_PEM is required');
  if (typeof trustedPublicKeySha256 !== 'string' || !trustedPublicKeySha256.trim()) {
    throw new Error('MALGUARD_RELEASE_PUBLIC_KEY_SHA256 is required');
  }
  if (typeof expectedSourceCommit !== 'string' || !expectedSourceCommit.trim()) {
    throw new Error('MALGUARD_EXPECTED_SOURCE_COMMIT is required');
  }

  const packagePath = path.resolve(packageArg);
  const manifest = JSON.parse(fs.readFileSync(path.resolve(manifestArg), 'utf8'));
  const signature = fs.readFileSync(path.resolve(signatureArg), 'utf8').trim();
  const currentVersion = process.env.MALGUARD_CURRENT_VERSION || '0.0.0';
  const expectedChannel = process.env.MALGUARD_RELEASE_CHANNEL || 'stable';

  verifySignedRelease({
    manifest,
    signature,
    publicKeyPem,
    trustedPublicKeySha256,
    packagePath,
    currentVersion,
    expectedChannel,
    expectedSourceCommit,
  });
  console.log(`✓ Signed release verified: ${path.basename(packagePath)} from trusted source commit ${manifest.sourceCommit}`);
}

if (require.main === module) {
  try { main(); } catch (error) { console.error(error.message || error); process.exit(1); }
}

module.exports = { main };
