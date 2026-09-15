'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.resolve(__dirname, '..');
const version = fs.readFileSync(path.join(ROOT, 'DESKTOP-VERSION'), 'utf8').trim();
const OUT = path.join(ROOT, 'dist', `malguard-desktop-${version}`);

function fail(message) { throw new Error(`RELEASE_GATE_FAILED: ${message}`); }
function sha256(file) { return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'); }
function walk(dir, base = dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isSymbolicLink()) fail(`symlink present: ${path.relative(base, full)}`);
    if (entry.isDirectory()) walk(full, base, out);
    else if (entry.isFile()) out.push(path.relative(base, full).split(path.sep).join('/'));
    else fail(`unsupported filesystem entry: ${path.relative(base, full)}`);
  }
  return out;
}

if (!fs.existsSync(OUT)) fail('portable package is missing');
const manifestPath = path.join(OUT, 'PACKAGE-MANIFEST.json');
const sumsPath = path.join(OUT, 'SHA256SUMS.txt');
if (!fs.existsSync(manifestPath) || !fs.existsSync(sumsPath)) fail('manifest or checksum file missing');
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
if (manifest.schemaVersion !== '1.0.0') fail('unsupported package manifest schema');
if (manifest.product !== 'MalGuard Desktop') fail('unexpected product');
if (manifest.desktopVersion !== version) fail('desktop version mismatch');
if (manifest.entrypoint !== 'desktop-app/server.js') fail('unexpected entrypoint');
if (!fs.existsSync(path.join(OUT, manifest.entrypoint))) fail('entrypoint missing');

const files = walk(OUT).sort();
if (files.length !== manifest.fileCount) fail(`file count mismatch: expected ${manifest.fileCount}, got ${files.length}`);
const forbidden = files.filter(file => {
  const base = path.posix.basename(file).toLowerCase();
  const ext = path.posix.extname(base);
  return base === '.env' || base.startsWith('.env.') || base === 'abusech-auth.dpapi' || ['.pem','.p12','.pfx','.key'].includes(ext);
});
if (forbidden.length) fail(`secret-like files present: ${forbidden.join(', ')}`);

const expected = new Map();
for (const line of fs.readFileSync(sumsPath, 'utf8').trim().split(/\r?\n/)) {
  const match = /^([a-f0-9]{64})  (.+)$/.exec(line);
  if (!match) fail(`malformed checksum line: ${line}`);
  if (expected.has(match[2])) fail(`duplicate checksum entry: ${match[2]}`);
  expected.set(match[2], match[1]);
}
const integrityFiles = files.filter(file => file !== 'SHA256SUMS.txt');
if (expected.size !== integrityFiles.length) fail('checksum coverage mismatch');
for (const file of integrityFiles) {
  if (!expected.has(file)) fail(`missing checksum: ${file}`);
  if (sha256(path.join(OUT, file)) !== expected.get(file)) fail(`checksum mismatch: ${file}`);
}

const forbiddenContent = [
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
  /MALGUARD_ABUSECH_AUTH_KEY\s*=\s*[^\s]+/,
  /MALGUARD_ENTITLEMENT_TOKEN\s*=\s*[^\s]+/,
];
for (const file of files.filter(f => /\.(?:js|json|md|txt|yml|yaml)$/i.test(f))) {
  const text = fs.readFileSync(path.join(OUT, file), 'utf8');
  for (const pattern of forbiddenContent) if (pattern.test(text)) fail(`credential-like content in ${file}`);
}

console.log(`✓ Release candidate gate: ${files.length} files, manifest/checksums/secrets PASS`);
