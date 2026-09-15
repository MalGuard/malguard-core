'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { SettingsStore } = require('../desktop-app/settings-store.js');

(async () => {
  const root = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'malguard-settings-'));
  const file = path.join(root, 'settings.json');
  const store = new SettingsStore(file);
  const game = path.join(root, 'game');
  const quarantine = path.join(root, 'quarantine');
  const staging = path.join(root, 'staging');

  const saved = await store.save({ watchRoots: [game, game], quarantineRoot: quarantine, stagingRoot: staging });
  assert.equal(saved.watchRoots.length, 1, 'duplicate protected roots should be deduplicated');
  const loaded = store.loadSync();
  assert.deepEqual(loaded.watchRoots, [path.resolve(game)]);
  assert.equal(loaded.quarantineRoot, path.resolve(quarantine));

  await assert.rejects(
    () => store.save({ watchRoots: [game], quarantineRoot: path.join(game, 'quarantine'), stagingRoot: staging }),
    err => err && err.code === 'AUXILIARY_ROOT_INSIDE_WATCH_ROOT'
  );
  await assert.rejects(
    () => store.save({ watchRoots: [], quarantineRoot: quarantine, stagingRoot: path.join(quarantine, 'stage') }),
    err => err && err.code === 'AUXILIARY_ROOTS_OVERLAP'
  );

  await fs.promises.rm(root, { recursive: true, force: true });
  console.log('✓ Settings store: atomic persistence, root dedupe and unsafe-overlap rejection PASS');
})().catch(error => { console.error(error.stack || error); process.exit(1); });
