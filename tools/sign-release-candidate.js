'use strict';

const fs = require('fs');
const path = require('path');
const { buildReleaseManifest, signReleaseManifest } = require('../desktop-app/update/release-trust.js');

function main() {
  if (process.env.GITHUB_ACTIONS === 'true') {
    throw new Error('OFFLINE_RELEASE_SIGNING_REQUIRED: release signing private keys must never be exposed to GitHub Actions');
  }
  const archiveArg = process.argv[2];
  if (!archiveArg) throw new Error('usage: node tools/sign-release-candidate.js <release-package>');
  const archive = path.resolve(archiveArg);
  const root = path.resolve(__dirname, '..');
  const version = fs.readFileSync(path.join(root, 'DESKTOP-VERSION'), 'utf8').trim().replace(/-dev$/, '');
  const sourceCommit = process.env.MALGUARD_RELEASE_SOURCE_COMMIT;
  const privateKeyPem = process.env.MALGUARD_RELEASE_SIGNING_PRIVATE_KEY_PEM;
  const manifest = buildReleaseManifest({ version, channel: 'stable', packagePath: archive, sourceCommit });
  const signature = signReleaseManifest(manifest, privateKeyPem);
  const manifestPath = `${archive}.manifest.json`;
  const signaturePath = `${archive}.manifest.sig`;
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n', { flag: 'wx', mode: 0o644 });
  fs.writeFileSync(signaturePath, signature + '\n', { flag: 'wx', mode: 0o644 });
  console.log(`Signed release metadata created for ${path.basename(archive)}; private key was not persisted.`);
  console.log(`Manifest: ${manifestPath}`);
  console.log(`Signature: ${signaturePath}`);
}

if (require.main === module) {
  try { main(); } catch (error) { console.error(error.message || error); process.exit(1); }
}

module.exports = { main };
