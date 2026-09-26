'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const DIST = path.join(ROOT, 'dist');
const desktopVersion = fs.readFileSync(path.join(ROOT, 'DESKTOP-VERSION'), 'utf8').trim();
const OUT = path.join(DIST, `malguard-desktop-${desktopVersion}`);
const SOURCE_COMMIT_RE = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/;

const ROOT_FILES = [
  'LICENSE',
  'SECURITY.md',
  'PRIVACY.md',
  'VERSION',
  'DESKTOP-VERSION',
  'rules.json',
  'malguard-contract.js',
  'engine.js',
  'multilayer.js',
  'gta-mod-detector.js',
  'archive-inspector.js',
  'archive-entry-reader.js',
  'script-analyzer.js',
  'app.js',
];

const RUNTIME_DIRS = [
  'desktop-app',
  'desktop-guard',
];

const FORBIDDEN_BASENAMES = new Set([
  '.env',
  'abusech-auth.dpapi',
]);
const FORBIDDEN_EXTENSIONS = new Set(['.pem', '.p12', '.pfx', '.key']);

function git(args) {
  const result = spawnSync('git', args, { cwd: ROOT, encoding: 'utf8', windowsHide: true });
  if (result.status !== 0) throw new Error(`git ${args.join(' ')} failed: ${(result.stderr || '').trim()}`);
  return result.stdout.trim();
}

function resolveSourceCommit() {
  const envCommit = String(process.env.MALGUARD_SOURCE_COMMIT || process.env.GITHUB_SHA || '').trim().toLowerCase();
  let head = '';
  try { head = git(['rev-parse', 'HEAD']).toLowerCase(); } catch (_) {
    if (!envCommit) throw new Error('Cannot establish source commit provenance; provide MALGUARD_SOURCE_COMMIT from a trusted build environment');
  }
  const sourceCommit = envCommit || head;
  if (!SOURCE_COMMIT_RE.test(sourceCommit)) throw new Error('Invalid source commit provenance');
  if (head && sourceCommit !== head) throw new Error(`Source commit provenance mismatch: expected ${sourceCommit}, checked out ${head}`);
  if (head) {
    const dirtyTracked = git(['status', '--porcelain', '--untracked-files=no']);
    if (dirtyTracked) throw new Error('Refusing to build release package from a dirty tracked source tree');
  }
  return sourceCommit;
}

function rejectSecretLikePath(relativePath) {
  const base = path.basename(relativePath).toLowerCase();
  const ext = path.extname(base);
  if (FORBIDDEN_BASENAMES.has(base) || base.startsWith('.env.')) {
    throw new Error(`Refusing to package secret-like file: ${relativePath}`);
  }
  if (FORBIDDEN_EXTENSIONS.has(ext)) {
    throw new Error(`Refusing to package credential material: ${relativePath}`);
  }
}

function ensureRegularFile(source, relativePath) {
  const stat = fs.lstatSync(source);
  if (stat.isSymbolicLink()) throw new Error(`Refusing symlink in package: ${relativePath}`);
  if (!stat.isFile()) throw new Error(`Expected regular file: ${relativePath}`);
}

function copyFile(relativePath) {
  rejectSecretLikePath(relativePath);
  const source = path.join(ROOT, relativePath);
  ensureRegularFile(source, relativePath);
  const target = path.join(OUT, relativePath);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.copyFileSync(source, target);
}

function copyTree(relativeDir) {
  const sourceDir = path.join(ROOT, relativeDir);
  const stat = fs.lstatSync(sourceDir);
  if (stat.isSymbolicLink() || !stat.isDirectory()) throw new Error(`Unsafe runtime directory: ${relativeDir}`);
  for (const entry of fs.readdirSync(sourceDir, { withFileTypes: true })) {
    const relativePath = path.join(relativeDir, entry.name);
    if (entry.isSymbolicLink()) throw new Error(`Refusing symlink in package: ${relativePath}`);
    if (entry.isDirectory()) copyTree(relativePath);
    else if (entry.isFile()) copyFile(relativePath);
    else throw new Error(`Unsupported filesystem entry: ${relativePath}`);
  }
}

function walkFiles(dir, base = dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walkFiles(full, base, out);
    else if (entry.isFile()) out.push(path.relative(base, full).split(path.sep).join('/'));
  }
  return out;
}

function sha256(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

const sourceCommit = resolveSourceCommit();

fs.rmSync(OUT, { recursive: true, force: true });
fs.mkdirSync(OUT, { recursive: true });

for (const file of ROOT_FILES) copyFile(file);
for (const dir of RUNTIME_DIRS) copyTree(dir);

const runtimePackage = {
  name: 'malguard-desktop-runtime',
  version: desktopVersion.replace(/-dev$/, ''),
  private: true,
  type: 'commonjs',
  engines: { node: '>=20' },
  scripts: { start: 'node --require ./desktop-app/integrity/preload.js --require ./desktop-app/health/preload.js desktop-app/server.js' },
};
fs.writeFileSync(path.join(OUT, 'package.json'), JSON.stringify(runtimePackage, null, 2) + '\n', 'utf8');

const preManifestFiles = walkFiles(OUT).sort();
const manifest = {
  schemaVersion: '1.0.0',
  product: 'MalGuard Desktop',
  desktopVersion,
  sourceCommit,
  entrypoint: 'desktop-app/server.js',
  node: '>=20',
  fileCount: preManifestFiles.length + 2,
};
fs.writeFileSync(path.join(OUT, 'PACKAGE-MANIFEST.json'), JSON.stringify(manifest, null, 2) + '\n', 'utf8');

const hashedFiles = walkFiles(OUT)
  .filter(file => file !== 'SHA256SUMS.txt')
  .sort();
const sums = hashedFiles.map(file => `${sha256(path.join(OUT, file))}  ${file}`).join('\n') + '\n';
fs.writeFileSync(path.join(OUT, 'SHA256SUMS.txt'), sums, 'utf8');

console.log(`Portable package created: ${path.relative(ROOT, OUT)}`);
console.log(`Source commit: ${sourceCommit}`);
console.log(`Runtime files: ${manifest.fileCount}`);
