'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { SettingsStore } = require('../desktop-app/settings-store.js');
const { SafeSelfHeal } = require('../desktop-app/health/self-heal.js');

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'malguard-self-heal-'));
class TestSettingsStore extends SettingsStore {
  defaults() {
    return {
      schemaVersion: '1.0.0',
      watchRoots: [],
      quarantineRoot: path.join(root, 'quarantine'),
      stagingRoot: path.join(root, 'staging'),
      updatedAt: 0,
    };
  }
}

try {
  const settingsPath = path.join(root, 'config', 'settings.json');
  fs.mkdirSync(path.dirname(settingsPath), { recursive: true });
  fs.writeFileSync(settingsPath, '{not-json', 'utf8');
  const store = new TestSettingsStore(settingsPath);
  const healer = new SafeSelfHeal({ settingsStore: store });
  const first = healer.repairSync();
  assert.equal(first.ok, true, JSON.stringify(first));
  assert.equal(first.repaired, true);
  assert.ok(fs.existsSync(settingsPath));
  assert.ok(fs.existsSync(path.join(root, 'quarantine')));
  assert.ok(fs.existsSync(path.join(root, 'staging')));
  assert.ok(fs.readdirSync(path.dirname(settingsPath)).some(name => name.startsWith('settings.json.corrupt-')));

  const second = healer.repairSync();
  assert.equal(second.ok, true, JSON.stringify(second));
  assert.equal(second.settingsState, 'valid');
  assert.equal(second.blockers.length, 0);
} finally {
  fs.rmSync(root, { recursive: true, force: true });
}

console.log('✓ Safe self-heal: corrupt settings backup, clean defaults, app-owned directory repair and idempotent health PASS');
