'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const BACKEND_VERSION = '0.1.0';
const PROTOCOL_VERSION = '1.0.0';
const SERIAL_PREFIX = 'MALGUARD_VM_EVENT_V1 ';
const MAX_SAMPLE_BYTES = 64 * 1024 * 1024;
const MAX_SERIAL_BYTES = 2 * 1024 * 1024;

function sha256Buffer(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

async function sha256File(filePath) {
  const hash = crypto.createHash('sha256');
  const handle = await fs.promises.open(filePath, 'r');
  try {
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let position = 0;
    while (true) {
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, position);
      if (!bytesRead) break;
      hash.update(buffer.subarray(0, bytesRead));
      position += bytesRead;
    }
  } finally {
    await handle.close();
  }
  return hash.digest('hex');
}

async function regularFile(filePath, { executable = false } = {}) {
  if (!filePath) return { ok: false, code: 'PATH_NOT_CONFIGURED' };
  try {
    const stat = await fs.promises.lstat(filePath);
    if (!stat.isFile() || stat.isSymbolicLink()) return { ok: false, code: 'NOT_REGULAR_FILE' };
    if (stat.size <= 0) return { ok: false, code: 'EMPTY_FILE' };
    if (executable) await fs.promises.access(filePath, fs.constants.X_OK);
    return { ok: true, size: stat.size, mtimeMs: stat.mtimeMs };
  } catch (error) {
    return { ok: false, code: error && error.code === 'ENOENT' ? 'NOT_FOUND' : 'NOT_ACCESSIBLE' };
  }
}

function qemuOptionPath(filePath) {
  // QEMU drive option values escape commas by doubling them.
  return String(filePath).replace(/,/g, ',,');
}

function decodeSerialEvent(line) {
  if (typeof line !== 'string' || !line.startsWith(SERIAL_PREFIX)) return null;
  const encoded = line.slice(SERIAL_PREFIX.length).trim();
  if (!encoded || encoded.length > 1024 * 1024) return null;
  try {
    const json = Buffer.from(encoded, 'base64url').toString('utf8');
    const parsed = JSON.parse(json);
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch (_) {
    return null;
  }
}

class MalGuardVmBackend {
  constructor({
    qemuPath = process.env.MALGUARD_VM_QEMU_PATH || null,
    guestImagePath = process.env.MALGUARD_VM_GUEST_IMAGE || null,
    guestImageSha256 = process.env.MALGUARD_VM_GUEST_SHA256 || null,
    timeoutMs = 45000,
    observeSeconds = 8,
    memoryMb = 2048,
    sessionRoot = null,
    softwareEmulation = true,
  } = {}) {
    this.qemuPath = qemuPath ? path.resolve(qemuPath) : null;
    this.guestImagePath = guestImagePath ? path.resolve(guestImagePath) : null;
    this.guestImageSha256 = guestImageSha256 ? String(guestImageSha256).toLowerCase() : null;
    this.timeoutMs = Math.max(10000, Number(timeoutMs) || 45000);
    this.observeSeconds = Math.max(1, Math.min(20, Number(observeSeconds) || 8));
    this.memoryMb = Math.max(1024, Number(memoryMb) || 2048);
    this.sessionRoot = path.resolve(sessionRoot || path.join(os.tmpdir(), 'malguard-portable-vm'));
    this.softwareEmulation = softwareEmulation !== false;
    this._guestVerification = null;
    this._acceptance = { containment: false, isolation: false };
  }

  async _verifyGuestImage() {
    const file = await regularFile(this.guestImagePath);
    if (!file.ok) return { ok: false, code: `GUEST_IMAGE_${file.code}` };
    if (!/^[a-f0-9]{64}$/.test(this.guestImageSha256 || '')) {
      return { ok: false, code: 'GUEST_IMAGE_SHA256_REQUIRED' };
    }
    const cacheKey = `${this.guestImagePath}:${file.size}:${file.mtimeMs}:${this.guestImageSha256}`;
    if (this._guestVerification && this._guestVerification.cacheKey === cacheKey) return this._guestVerification;
    const actual = await sha256File(this.guestImagePath);
    const ok = crypto.timingSafeEqual(Buffer.from(actual, 'hex'), Buffer.from(this.guestImageSha256, 'hex'));
    this._guestVerification = {
      ok,
      code: ok ? 'GUEST_IMAGE_VERIFIED' : 'GUEST_IMAGE_HASH_MISMATCH',
      actualSha256: actual,
      cacheKey,
    };
    return this._guestVerification;
  }

  async capabilities() {
    const qemu = await regularFile(this.qemuPath, { executable: true });
    const guest = await this._verifyGuestImage();
    const available = qemu.ok === true && guest.ok === true;
    const releaseGrade = available && this._acceptance.containment === true && this._acceptance.isolation === true;
    const blockers = [];
    if (!qemu.ok) blockers.push('malguard_vm_engine_unavailable');
    if (!guest.ok) blockers.push(guest.code || 'malguard_vm_guest_unavailable');
    if (available && !this._acceptance.containment) blockers.push('malguard_vm_containment_self_test_pending');
    if (available && !this._acceptance.isolation) blockers.push('malguard_vm_isolation_self_test_pending');
    return {
      backend: 'malguard-vm',
      backendVersion: BACKEND_VERSION,
      protocolVersion: PROTOCOL_VERSION,
      available,
      releaseGrade,
      qemuPresent: qemu.ok === true,
      guestImageVerified: guest.ok === true,
      acceleration: this.softwareEmulation ? 'tcg-software-emulation' : 'configured-hardware-acceleration',
      requiresWindowsSandbox: false,
      requiresVtxAmdV: this.softwareEmulation ? false : null,
      isolation: {
        network: 'disabled',
        clipboard: 'not-exposed',
        hostWritableShares: false,
        inputMedia: 'read-only-fat',
        guestDisk: 'read-only-with-ephemeral-snapshot',
        disposableVm: true,
        telemetryChannel: 'serial-only',
        memoryMb: this.memoryMb,
        wallClockTimeoutMs: this.timeoutMs,
      },
      blockers,
    };
  }

  buildLaunchArgs({ inputDir }) {
    if (!this.guestImagePath) throw new Error('MalGuard VM guest image is not configured');
    if (!inputDir) throw new Error('MalGuard VM input directory is required');
    const args = [
      '-machine', this.softwareEmulation ? 'q35,accel=tcg' : 'q35',
      '-m', String(this.memoryMb),
      '-smp', '2',
      '-snapshot',
      '-no-reboot',
      '-no-shutdown',
      '-nodefaults',
      '-display', 'none',
      '-monitor', 'none',
      '-serial', 'stdio',
      '-nic', 'none',
      '-usb', 'off',
      '-drive', `file=${qemuOptionPath(this.guestImagePath)},if=ide,media=disk,readonly=on`,
      '-drive', `file=fat:ro:${qemuOptionPath(path.resolve(inputDir))},format=raw,if=ide,media=disk,readonly=on`,
    ];
    return args;
  }

  async runContainmentSelfTest() {
    this._acceptance.containment = false;
    const caps = await this.capabilities();
    if (!caps.available) return { ok: false, code: caps.blockers[0] || 'MALGUARD_VM_UNAVAILABLE' };
    const probeDir = await fs.promises.mkdtemp(path.join(this.sessionRoot, 'containment-')).catch(async () => {
      await fs.promises.mkdir(this.sessionRoot, { recursive: true });
      return fs.promises.mkdtemp(path.join(this.sessionRoot, 'containment-'));
    });
    try {
      const args = this.buildLaunchArgs({ inputDir: probeDir });
      const requiredPairs = [
        ['-nic', 'none'], ['-monitor', 'none'], ['-display', 'none'], ['-snapshot', null], ['-usb', 'off'],
      ];
      const ok = requiredPairs.every(([flag, value]) => {
        const index = args.indexOf(flag);
        return index >= 0 && (value == null || args[index + 1] === value);
      }) && args.filter(value => typeof value === 'string' && value.includes('readonly=on')).length >= 2;
      this._acceptance.containment = ok;
      return ok
        ? { ok: true, code: 'MALGUARD_VM_CONTAINMENT_CONFIG_ACCEPTED', softwareEmulation: this.softwareEmulation }
        : { ok: false, code: 'MALGUARD_VM_CONTAINMENT_CONFIG_FAILED' };
    } finally {
      await fs.promises.rm(probeDir, { recursive: true, force: true }).catch(() => {});
    }
  }

  async _launchRequest(request, inputFiles = []) {
    const caps = await this.capabilities();
    if (!caps.available) return { ok: false, code: caps.blockers[0] || 'MALGUARD_VM_UNAVAILABLE' };
    const sessionId = request.sessionId || crypto.randomUUID();
    const root = await fs.promises.mkdtemp(path.join(this.sessionRoot, 'session-')).catch(async () => {
      await fs.promises.mkdir(this.sessionRoot, { recursive: true });
      return fs.promises.mkdtemp(path.join(this.sessionRoot, 'session-'));
    });
    const inputDir = path.join(root, 'input');
    await fs.promises.mkdir(inputDir, { recursive: true, mode: 0o700 });
    try {
      const sealedRequest = { ...request, schemaVersion: PROTOCOL_VERSION, sessionId };
      await fs.promises.writeFile(path.join(inputDir, 'MALGUARD-REQUEST.json'), JSON.stringify(sealedRequest), { flag: 'wx', mode: 0o600 });
      for (const file of inputFiles) {
        await fs.promises.writeFile(path.join(inputDir, file.name), file.bytes, { flag: 'wx', mode: 0o600 });
      }
      const args = this.buildLaunchArgs({ inputDir });
      return await new Promise((resolve) => {
        let settled = false;
        let stdout = '';
        let stderrBytes = 0;
        const child = spawn(this.qemuPath, args, {
          stdio: ['ignore', 'pipe', 'pipe'],
          windowsHide: true,
          shell: false,
        });
        const finish = (result) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          try { if (!child.killed) child.kill('SIGKILL'); } catch (_) {}
          resolve(result);
        };
        const inspect = () => {
          const lines = stdout.split(/\r?\n/);
          for (const line of lines) {
            const event = decodeSerialEvent(line);
            if (!event || event.sessionId !== sessionId || event.schemaVersion !== PROTOCOL_VERSION) continue;
            if (event.type === 'result' || event.type === 'self-test-result') {
              return finish({ ok: true, event, sessionId, launchArgs: args });
            }
          }
          return null;
        };
        child.stdout.on('data', chunk => {
          stdout += chunk.toString('utf8');
          if (Buffer.byteLength(stdout, 'utf8') > MAX_SERIAL_BYTES) return finish({ ok: false, code: 'MALGUARD_VM_SERIAL_OUTPUT_TOO_LARGE' });
          inspect();
        });
        child.stderr.on('data', chunk => {
          stderrBytes += chunk.length;
          if (stderrBytes > 256 * 1024) finish({ ok: false, code: 'MALGUARD_VM_STDERR_TOO_LARGE' });
        });
        const timer = setTimeout(() => finish({ ok: false, code: 'MALGUARD_VM_TIMEOUT' }), this.timeoutMs);
        child.once('error', error => finish({ ok: false, code: 'MALGUARD_VM_LAUNCH_FAILED', detail: error.message }));
        child.once('exit', code => {
          if (!settled) finish({ ok: false, code: 'MALGUARD_VM_EXITED_WITHOUT_ATTESTATION', exitCode: code });
        });
      });
    } finally {
      await fs.promises.rm(root, { recursive: true, force: true }).catch(() => {});
    }
  }

  async runIsolationSelfTest() {
    this._acceptance.isolation = false;
    const sessionId = crypto.randomUUID();
    const result = await this._launchRequest({ type: 'self-test', sessionId });
    const event = result && result.event;
    const ok = result.ok === true && event && event.type === 'self-test-result' &&
      event.sandboxReached === true && event.networkDisabled === true &&
      event.inputReadOnly === true && event.hostWritableShares === false && event.error == null;
    this._acceptance.isolation = ok;
    return ok
      ? { ok: true, code: 'MALGUARD_VM_ISOLATION_CERTIFIED', details: event }
      : { ok: false, code: result.code || 'MALGUARD_VM_ISOLATION_SELF_TEST_FAILED', details: event || null };
  }

  async analyze(samplePath, expectedIdentity = null) {
    const caps = await this.capabilities();
    if (caps.releaseGrade !== true) {
      return { ok: false, verdict: 'inconclusive', code: 'MALGUARD_VM_ACCEPTANCE_PENDING', backend: caps };
    }
    const resolved = path.resolve(samplePath);
    const statBefore = await fs.promises.lstat(resolved);
    if (!statBefore.isFile() || statBefore.isSymbolicLink() || statBefore.size <= 0 || statBefore.size > MAX_SAMPLE_BYTES) {
      return { ok: false, verdict: 'inconclusive', code: 'INVALID_SANDBOX_SAMPLE' };
    }
    const bytes = await fs.promises.readFile(resolved);
    const statAfter = await fs.promises.lstat(resolved);
    if (statAfter.isSymbolicLink() || statAfter.size !== statBefore.size || statAfter.mtimeMs !== statBefore.mtimeMs || bytes.length !== statBefore.size) {
      return { ok: false, verdict: 'inconclusive', code: 'SANDBOX_SAMPLE_CHANGED_DURING_STAGING' };
    }
    const sha256 = sha256Buffer(bytes);
    if (expectedIdentity && expectedIdentity.sha256 && expectedIdentity.sha256 !== sha256) {
      return { ok: false, verdict: 'inconclusive', code: 'SANDBOX_SAMPLE_IDENTITY_MISMATCH' };
    }
    const ext = path.extname(resolved).toLowerCase();
    const sampleName = `sample${ext}`;
    const sessionId = crypto.randomUUID();
    const result = await this._launchRequest({
      type: 'analyze',
      sessionId,
      sampleName,
      sampleSha256: sha256,
      observeSeconds: this.observeSeconds,
      networkExpectedDisabled: true,
    }, [{ name: sampleName, bytes }]);
    if (!result.ok || !result.event) {
      return { ok: false, verdict: 'inconclusive', code: result.code || 'MALGUARD_VM_ANALYSIS_FAILED', sampleSha256: sha256 };
    }
    const event = result.event;
    const execution = event.execution || null;
    const proven = event.type === 'result' && event.sampleSha256 === sha256 && event.networkDisabled === true &&
      execution && execution.attempted === true && execution.started === true;
    if (!proven) {
      return { ok: false, verdict: 'inconclusive', code: 'MALGUARD_VM_SAMPLE_EXECUTION_NOT_PROVEN', sampleSha256: sha256, telemetry: event };
    }
    const verdict = ['malicious', 'suspicious', 'inconclusive'].includes(event.verdict) ? event.verdict : 'inconclusive';
    return {
      ok: true,
      backend: 'malguard-vm',
      backendVersion: BACKEND_VERSION,
      verdict,
      sampleSha256: sha256,
      telemetry: event,
    };
  }
}

module.exports = {
  MalGuardVmBackend,
  BACKEND_VERSION,
  PROTOCOL_VERSION,
  SERIAL_PREFIX,
  decodeSerialEvent,
};
