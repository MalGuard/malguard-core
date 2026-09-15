'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { ProtectedFolderAclGate } = require('../desktop-guard/windows-agent/acl-protection.js');

(async () => {
  const root = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'malguard-acl-gate-'));
  const game = path.join(root, 'game');
  const state = path.join(root, 'state');
  await fs.promises.mkdir(game, { recursive: true });
  const gate = new ProtectedFolderAclGate({ roots: [game], stateRoot: state });
  const caps = gate.capabilities();
  assert.equal(typeof caps.threatModel, 'string');
  assert.match(caps.threatModel, /unprivileged/i);
  if (process.platform !== 'win32') {
    const status = await gate.status();
    assert.equal(status.supported, false);
    await assert.rejects(() => gate.protectAll(), err => err && err.code === 'ACL_GATE_UNSUPPORTED_PLATFORM');
  }

  const helper = fs.readFileSync(path.join(__dirname, '..', 'desktop-guard', 'windows-agent', 'windows-tools', 'acl-helper.ps1'), 'utf8');
  assert.match(helper, /O:SYG:SYD:P/);
  assert.match(helper, /;;;SY\)/);
  assert.match(helper, /;;;BA\)/);
  assert.match(helper, /;;;BU\)/);
  assert.doesNotMatch(helper, /Set-ExecutionPolicy/i);

  await fs.promises.rm(root, { recursive: true, force: true });
  console.log('✓ Protected-folder access gate: language-neutral ACL policy and unsupported-host fail-closed behavior PASS');
})().catch(error => { console.error(error.stack || error); process.exit(1); });
