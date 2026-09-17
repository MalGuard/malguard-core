'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const { canonicalize } = require('../update/secure-update.js');
const {
  MAX_RESULT_BYTES,
  validateTelemetry,
  evaluateTelemetry,
} = require('./telemetry-validator.js');

const MICROVM_BACKEND_VERSION = '0.1.0';
const MICROVM_IMAGE_SCHEMA = '1.0.0';
const MICROVM_EVIDENCE_SCHEMA = '1.0.0';
const MAX_SAMPLE_BYTES = 64 * 1024 * 1024;
const SUPPORTED_EXTENSIONS = new Set(['.exe', '.com', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js']);

function sha256Bytes(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

async function sha256File(filePath) {
  return sha256Bytes(await fs.promises.readFile(filePath));
}

function verifyMicroVmImage({ imagePath, manifest, signature, publicKeyPem }) {
  if (!manifest || manifest.schemaVersion !== MICROVM_IMAGE_SCHEMA || manifest.product !== 'MalGuard MicroVM') {
    throw new Error('invalid MalGuard MicroVM image manifest');
  }
  if (typeof manifest.imageId !== 'string' || !/^[a-z0-9._-]{3,64}$/i.test(manifest.imageId)) {
    throw new Error('invalid MalGuard MicroVM image id');
  }
  if (typeof manifest.version !== 'string' || !manifest.version) throw new Error('invalid MalGuard MicroVM image version');
  if (!manifest.image || !/^[a-f0-9]{64}$/.test(String(manifest.image.sha256 || ''))) {
    throw new Error('invalid MalGuard MicroVM image hash');
  }
  if (!Number.isSafeInteger(manifest.image.size) || manifest.image.size <= 0) {
    throw new Error('invalid MalGuard MicroVM image size');
  }
  const resolved = path.resolve(imagePath || '');
  const stat = fs.lstatSync(resolved);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size !== manifest.image.size) {
    throw new Error('MalGuard MicroVM image identity mismatch');
  }
  const key = crypto.createPublicKey(publicKeyPem);
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('MalGuard MicroVM image key must be Ed25519');
  const signatureBytes = Buffer.from(String(signature || '').trim(), 'base64');
  if (!signatureBytes.length || !crypto.verify(null, Buffer.from(canonicalize(manifest), 'utf8'), key, signatureBytes)) {
    throw new Error('MalGuard MicroVM image signature verification failed');
  }
  const actualSha256 = crypto.createHash('sha256').update(fs.readFileSync(resolved)).digest('hex');
  if (!crypto.timingSafeEqual(Buffer.from(actualSha256, 'hex'), Buffer.from(manifest.image.sha256, 'hex'))) {
    throw new Error('MalGuard MicroVM image sha256 mismatch');
  }
  return { ok: true, imageId: manifest.imageId, version: manifest.version, sha256: actualSha256, size: stat.size };
}

function validateMicroVmEvidence(evidence, { sessionId, imageSha256, requireSampleExecution = false } = {}) {
  if (!evidence || evidence.schemaVersion !== MICROVM_EVIDENCE_SCHEMA) return { ok: false, code: 'MICROVM_EVIDENCE_SCHEMA_INVALID' };
  if (typeof sessionId === 'string' && evidence.sessionId !== sessionId) return { ok: false, code: 'MICROVM_EVIDENCE_SESSION_MISMATCH' };
  if (typeof imageSha256 === 'string' && evidence.imageSha256 !== imageSha256) return { ok: false, code: 'MICROVM_EVIDENCE_IMAGE_MISMATCH' };
  const required = [
    'vmBooted',
    'guestAgentAuthenticated',
    'networkDisabled',
    'hostInputReadOnly',
    'disposableOverlay',
    'hostClipboardDisabled',
  ];
  for (const key of required) if (evidence[key] !== true) return { ok: false, code: `MICROVM_EVIDENCE_${key.toUpperCase()}_REQUIRED` };
  if (requireSampleExecution) {
    if (evidence.sampleAttempted !== true) return { ok: false, code: 'MICROVM_SAMPLE_EXECUTION_NOT_ATTEMPTED' };
    if (evidence.sampleStarted !== true) return { ok: false, code: 'MICROVM_SAMPLE_EXECUTION_NOT_STARTED' };
  }
  return { ok: true };
}

class MalGuardMicroVMBackend {
  constructor({
    launcherPath = null,
    imagePath = null,
    imageManifestPath = null,
    imageSignaturePath = null,
    imagePublicKeyPem = null,
    timeoutMs = 30000,
    observeSeconds = 8,
    memoryMb = 2048,
    sessionRoot = null,
    preserveSessions = false,
  } = {}) {
    this.launcherPath = path.resolve(launcherPath || path.join(__dirname, 'bin', 'MalGuardMicroVMHost.exe'));
    this.imagePath = path.resolve(imagePath || path.join(__dirname, 'microvm', 'malguard-microvm-base.vhdx'));
    this.imageManifestPath = path.resolve(imageManifestPath || `${this.imagePath}.manifest.json`);
    this.imageSignaturePath = path.resolve(imageSignaturePath || `${this.imagePath}.manifest.sig`);
    this.imagePublicKeyPem = imagePublicKeyPem || process.env.MALGUARD_MICROVM_IMAGE_PUBLIC_KEY_PEM || '';
    this.timeoutMs = Math.max(5000, Number(timeoutMs) || 30000);
    this.observeSeconds = Math.max(1, Math.min(20, Number(observeSeconds) || 8));
    this.memoryMb = Math.max(512, Number(memoryMb) || 2048);
    this.sessionRoot = path.resolve(sessionRoot || path.join(os.tmpdir(), 'malguard-microvm'));
    this.preserveSessions = preserveSessions === true;
    this._acceptance = { containment: false, isolation: false };
    this._trustedImage = null;
  }

  async _loadTrustedImage() {
    const manifest = JSON.parse(await fs.promises.readFile(this.imageManifestPath, 'utf8'));
    const signature = (await fs.promises.readFile(this.imageSignaturePath, 'utf8')).trim();
    const trust = verifyMicroVmImage({
      imagePath: this.imagePath,
      manifest,
      signature,
      publicKeyPem: this.imagePublicKeyPem,
    });
    this._trustedImage = { ...trust, manifest };
    return this._trustedImage;
  }

  async capabilities() {
    const blockers = [];
    let launcherPresent = false;
    let imageTrusted = false;
    let image = null;
    if (process.platform === 'win32') {
      try { await fs.promises.access(this.launcherPath, fs.constants.X_OK); launcherPresent = true; } catch (_) {}
    }
    try {
      image = await this._loadTrustedImage();
      imageTrusted = true;
    } catch (_) {}
    if (process.platform !== 'win32') blockers.push('microvm_windows_host_required');
    if (!launcherPresent) blockers.push('malguard_microvm_launcher_missing');
    if (!imageTrusted) blockers.push('malguard_microvm_trusted_image_missing');
    if (launcherPresent && imageTrusted && this._acceptance.containment !== true) blockers.push('malguard_microvm_containment_self_test_pending');
    if (launcherPresent && imageTrusted && this._acceptance.isolation !== true) blockers.push('malguard_microvm_isolation_self_test_pending');
    const available = process.platform === 'win32' && launcherPresent && imageTrusted;
    const releaseGrade = available && this._acceptance.containment === true && this._acceptance.isolation === true;
    return {
      backend: 'malguard-microvm',
      backendVersion: MICROVM_BACKEND_VERSION,
      platform: process.platform,
      available,
      releaseGrade,
      hardened: releaseGrade,
      launcherPresent,
      imageTrusted,
      image: image ? { imageId: image.imageId, version: image.version, sha256: image.sha256, size: image.size } : null,
      acceptance: { containment: this._acceptance.containment, isolation: this._acceptance.isolation, scope: 'current-process' },
      isolation: {
        network: 'disabled',
        clipboard: 'disabled',
        hostInput: 'read-only',
        disposableOverlay: true,
        persistentGuestWrites: false,
        guestAgentAuthentication: 'required',
        memoryMb: this.memoryMb,
        wallClockTimeoutMs: this.timeoutMs,
      },
      blockers,
    };
  }

  async _spawnLauncher(args, { timeoutMs = this.timeoutMs } = {}) {
    return new Promise((resolve) => {
      let stdout = '';
      let stderr = '';
      let settled = false;
      const child = spawn(this.launcherPath, args, { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true, shell: false });
      const finish = (result) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        try { if (!child.killed) child.kill(); } catch (_) {}
        resolve(result);
      };
      child.stdout.on('data', chunk => {
        stdout += chunk.toString('utf8');
        if (Buffer.byteLength(stdout, 'utf8') > 128 * 1024) finish({ ok: false, code: 'MICROVM_LAUNCHER_OUTPUT_TOO_LARGE' });
      });
      child.stderr.on('data', chunk => {
        stderr += chunk.toString('utf8');
        if (Buffer.byteLength(stderr, 'utf8') > 128 * 1024) finish({ ok: false, code: 'MICROVM_LAUNCHER_STDERR_TOO_LARGE' });
      });
      const timer = setTimeout(() => finish({ ok: false, code: 'MICROVM_LAUNCHER_TIMEOUT' }), timeoutMs);
      child.once('error', error => finish({ ok: false, code: 'MICROVM_LAUNCHER_START_FAILED', detail: error.message }));
      child.once('exit', code => finish({ ok: code === 0, code: code === 0 ? 'MICROVM_LAUNCHER_OK' : 'MICROVM_LAUNCHER_FAILED', exitCode: code, stdout, stderr }));
    });
  }

  async runContainmentSelfTest() {
    this._acceptance.containment = false;
    const caps = await this.capabilities();
    if (!caps.available) return { ok: false, code: 'MALGUARD_MICROVM_UNAVAILABLE', blockers: caps.blockers };
    const result = await this._spawnLauncher(['--self-test-json', '--image', this.imagePath]);
    if (!result.ok) return result;
    let parsed;
    try { parsed = JSON.parse(result.stdout.trim()); } catch (_) { return { ok: false, code: 'MICROVM_SELF_TEST_JSON_INVALID' }; }
    const ok = parsed && parsed.schemaVersion === '1.0.0' && parsed.ok === true &&
      parsed.hypervisorIsolation === true && parsed.memoryIsolation === true && parsed.processIsolation === true;
    this._acceptance.containment = ok;
    return ok ? { ok: true, details: parsed } : { ok: false, code: 'MICROVM_CONTAINMENT_SELF_TEST_FAILED', details: parsed || null };
  }

  async _prepareSession(samplePath, expectedIdentity = null) {
    const extension = path.extname(samplePath).toLowerCase();
    if (!SUPPORTED_EXTENSIONS.has(extension)) {
      const error = new Error('unsupported MicroVM sample type');
      error.code = 'SANDBOX_SAMPLE_TYPE_UNSUPPORTED';
      throw error;
    }
    const before = await fs.promises.lstat(samplePath);
    if (!before.isFile() || before.isSymbolicLink() || before.size <= 0 || before.size > MAX_SAMPLE_BYTES) {
      const error = new Error('invalid MicroVM sample');
      error.code = 'INVALID_SANDBOX_SAMPLE';
      throw error;
    }
    const bytes = await fs.promises.readFile(samplePath);
    const sampleSha256 = sha256Bytes(bytes);
    if (expectedIdentity && expectedIdentity.sha256 && expectedIdentity.sha256 !== sampleSha256) {
      const error = new Error('sample identity changed after preflight');
      error.code = 'SANDBOX_SAMPLE_IDENTITY_MISMATCH';
      throw error;
    }
    const sessionId = crypto.randomUUID();
    const root = path.join(this.sessionRoot, sessionId);
    const inputDir = path.join(root, 'input');
    const outputDir = path.join(root, 'output');
    await fs.promises.mkdir(inputDir, { recursive: true, mode: 0o700 });
    await fs.promises.mkdir(outputDir, { recursive: true, mode: 0o700 });
    const stagedSample = path.join(inputDir, `sample${extension}`);
    await fs.promises.writeFile(stagedSample, bytes, { flag: 'wx', mode: 0o400 });
    if (await sha256File(stagedSample) !== sampleSha256) {
      const error = new Error('MicroVM staging integrity mismatch');
      error.code = 'MICROVM_STAGING_INTEGRITY_FAILED';
      throw error;
    }
    return { sessionId, root, inputDir, outputDir, stagedSample, sampleSha256, extension };
  }

  async _cleanup(session) {
    if (!session || this.preserveSessions) return;
    await fs.promises.rm(session.root, { recursive: true, force: true }).catch(() => {});
  }

  async _runRequest(request, session, { requireSampleExecution }) {
    const requestPath = path.join(session.root, 'request.json');
    const resultPath = path.join(session.outputDir, 'result.json');
    await fs.promises.writeFile(requestPath, JSON.stringify(request, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
    const launched = await this._spawnLauncher(['--request', requestPath, '--result', resultPath]);
    if (!launched.ok) return { ok: false, code: launched.code, detail: launched.stderr || null };
    let stat;
    try { stat = await fs.promises.lstat(resultPath); } catch (_) { return { ok: false, code: 'MICROVM_RESULT_MISSING' }; }
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size <= 0 || stat.size > MAX_RESULT_BYTES) return { ok: false, code: 'MICROVM_RESULT_INVALID' };
    let parsed;
    try { parsed = JSON.parse((await fs.promises.readFile(resultPath, 'utf8')).replace(/^\uFEFF/, '')); }
    catch (_) { return { ok: false, code: 'MICROVM_RESULT_JSON_INVALID' }; }
    const evidenceCheck = validateMicroVmEvidence(parsed.evidence, {
      sessionId: session.sessionId,
      imageSha256: this._trustedImage && this._trustedImage.sha256,
      requireSampleExecution,
    });
    if (!evidenceCheck.ok) return evidenceCheck;
    return { ok: true, parsed };
  }

  async runIsolationSelfTest() {
    this._acceptance.isolation = false;
    if (this._acceptance.containment !== true) return { ok: false, code: 'MICROVM_CONTAINMENT_NOT_CERTIFIED' };
    const caps = await this.capabilities();
    if (!caps.available) return { ok: false, code: 'MALGUARD_MICROVM_UNAVAILABLE', blockers: caps.blockers };
    const session = { sessionId: crypto.randomUUID(), root: path.join(this.sessionRoot, `selftest-${crypto.randomUUID()}`) };
    session.inputDir = path.join(session.root, 'input');
    session.outputDir = path.join(session.root, 'output');
    await fs.promises.mkdir(session.inputDir, { recursive: true, mode: 0o700 });
    await fs.promises.mkdir(session.outputDir, { recursive: true, mode: 0o700 });
    try {
      const request = {
        schemaVersion: '1.0.0', mode: 'self-test', sessionId: session.sessionId,
        imagePath: this.imagePath, imageSha256: this._trustedImage.sha256,
        policy: { network: 'disabled', hostInput: 'read-only', clipboard: 'disabled', disposableOverlay: true },
      };
      const result = await this._runRequest(request, session, { requireSampleExecution: false });
      this._acceptance.isolation = result.ok === true;
      return result.ok ? { ok: true, evidence: result.parsed.evidence } : result;
    } finally {
      await this._cleanup(session);
    }
  }

  async analyze(samplePath, expectedIdentity = null) {
    const caps = await this.capabilities();
    if (!caps.releaseGrade) return { ok: false, verdict: 'inconclusive', code: caps.available ? 'MALGUARD_MICROVM_ACCEPTANCE_PENDING' : 'MALGUARD_MICROVM_UNAVAILABLE', backend: caps };
    let session;
    try { session = await this._prepareSession(path.resolve(samplePath), expectedIdentity); }
    catch (error) { return { ok: false, verdict: 'inconclusive', code: error.code || 'MICROVM_STAGING_FAILED', backend: caps }; }
    try {
      const request = {
        schemaVersion: '1.0.0', mode: 'analyze', sessionId: session.sessionId,
        imagePath: this.imagePath, imageSha256: this._trustedImage.sha256,
        sample: { path: session.stagedSample, sha256: session.sampleSha256, extension: session.extension },
        observeSeconds: this.observeSeconds,
        policy: { network: 'disabled', hostInput: 'read-only', clipboard: 'disabled', disposableOverlay: true, persistentGuestWrites: false },
      };
      const run = await this._runRequest(request, session, { requireSampleExecution: true });
      if (!run.ok) return { ok: false, verdict: 'inconclusive', code: run.code, backend: caps, sampleSha256: session.sampleSha256 };
      const telemetryCheck = validateTelemetry(run.parsed.telemetry, session.sessionId);
      if (!telemetryCheck.ok) return { ok: false, verdict: 'inconclusive', code: telemetryCheck.code, backend: caps, sampleSha256: session.sampleSha256 };
      const assessment = evaluateTelemetry(telemetryCheck.telemetry);
      return {
        ok: true,
        verdict: assessment.verdict,
        releaseGrade: true,
        backend: caps,
        sampleSha256: session.sampleSha256,
        telemetry: telemetryCheck.telemetry,
        microVmEvidence: run.parsed.evidence,
        behaviorAssessment: assessment,
        note: 'MalGuard MicroVM behavior telemetry can raise suspicion but never proves SAFE on its own.',
      };
    } finally {
      await this._cleanup(session);
    }
  }
}

module.exports = {
  MalGuardMicroVMBackend,
  MICROVM_BACKEND_VERSION,
  MICROVM_IMAGE_SCHEMA,
  MICROVM_EVIDENCE_SCHEMA,
  verifyMicroVmImage,
  validateMicroVmEvidence,
};
