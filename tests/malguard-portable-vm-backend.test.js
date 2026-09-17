'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {
  MalGuardVmBackend,
  SERIAL_PREFIX,
  decodeSerialEvent,
} = require('../desktop-app/sandbox/malguard-vm-backend.js');

(async () => {
  const root = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'malguard-portable-vm-test-'));
  try {
    const fakeEngine = path.join(root, process.platform === 'win32' ? 'qemu-system-x86_64.exe' : 'qemu-system-x86_64');
    const guestImage = path.join(root, 'malguard-windows-guest.vhdx');
    const inputDir = path.join(root, 'input');
    await fs.promises.mkdir(inputDir);
    await fs.promises.writeFile(fakeEngine, Buffer.from('harmless synthetic engine fixture\n'));
    if (process.platform !== 'win32') await fs.promises.chmod(fakeEngine, 0o700);
    const guestBytes = Buffer.from('harmless synthetic guest image fixture\n');
    await fs.promises.writeFile(guestImage, guestBytes);
    const guestSha256 = crypto.createHash('sha256').update(guestBytes).digest('hex');

    const backend = new MalGuardVmBackend({
      qemuPath: fakeEngine,
      guestImagePath: guestImage,
      guestImageSha256: guestSha256,
      softwareEmulation: true,
      sessionRoot: path.join(root, 'sessions'),
    });

    const caps = await backend.capabilities();
    assert.equal(caps.backend, 'malguard-vm');
    assert.equal(caps.qemuPresent, true);
    assert.equal(caps.guestImageVerified, true);
    assert.equal(caps.requiresWindowsSandbox, false);
    assert.equal(caps.requiresVtxAmdV, false);
    assert.equal(caps.acceleration, 'tcg-software-emulation');
    assert.equal(caps.releaseGrade, false, 'portable VM must remain fail-closed until live self-tests certify it');
    assert.equal(caps.isolation.network, 'disabled');
    assert.equal(caps.isolation.hostWritableShares, false);
    assert.equal(caps.isolation.inputMedia, 'read-only-fat');
    assert.equal(caps.isolation.telemetryChannel, 'serial-only');

    const args = backend.buildLaunchArgs({ inputDir });
    const nicIndex = args.indexOf('-nic');
    assert(nicIndex >= 0 && args[nicIndex + 1] === 'none', 'network must be disabled');
    const monitorIndex = args.indexOf('-monitor');
    assert(monitorIndex >= 0 && args[monitorIndex + 1] === 'none', 'QEMU monitor must be disabled');
    const serialIndex = args.indexOf('-serial');
    assert(serialIndex >= 0 && args[serialIndex + 1] === 'stdio', 'telemetry must use the controlled serial channel');
    assert(args.includes('-snapshot'), 'guest writes must be disposable');
    assert(args.some(value => typeof value === 'string' && value.startsWith('file=fat:ro:') && value.includes('readonly=on')), 'sample input must be exposed read-only');
    assert(args.some(value => typeof value === 'string' && value.includes('accel=tcg')), 'software emulation must not require VT-x/AMD-V');

    const event = {
      schemaVersion: '1.0.0',
      sessionId: '11111111-1111-4111-8111-111111111111',
      type: 'self-test-result',
      sandboxReached: true,
      networkDisabled: true,
      inputReadOnly: true,
      hostWritableShares: false,
      error: null,
    };
    const encoded = Buffer.from(JSON.stringify(event), 'utf8').toString('base64url');
    assert.deepEqual(decodeSerialEvent(`${SERIAL_PREFIX}${encoded}`), event);
    assert.equal(decodeSerialEvent('random guest output'), null);

    const wrongHashBackend = new MalGuardVmBackend({
      qemuPath: fakeEngine,
      guestImagePath: guestImage,
      guestImageSha256: '0'.repeat(64),
      softwareEmulation: true,
    });
    const badCaps = await wrongHashBackend.capabilities();
    assert.equal(badCaps.available, false);
    assert(badCaps.blockers.includes('GUEST_IMAGE_HASH_MISMATCH'));

    const sample = path.join(root, 'synthetic.cmd');
    await fs.promises.writeFile(sample, '@echo off\r\nexit /b 0\r\n');
    const denied = await backend.analyze(sample, null);
    assert.equal(denied.ok, false);
    assert.equal(denied.verdict, 'inconclusive');
    assert.equal(denied.code, 'MALGUARD_VM_ACCEPTANCE_PENDING');

    console.log('✓ MalGuard portable VM foundation: software emulation, no-network/read-only/snapshot policy, signed-image hash gate and fail-closed execution PASS');
  } finally {
    await fs.promises.rm(root, { recursive: true, force: true });
  }
})().catch(error => {
  console.error(error.stack || error);
  process.exit(1);
});
