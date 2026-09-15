'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const contract = require('../desktop-guard/guard-contract.js');
const protocol = require('../desktop-guard/windows-agent/protocol.js');
const { QuarantineStore } = require('../desktop-guard/windows-agent/quarantine-store.js');
const { WindowsUserSpaceGuardAgent } = require('../desktop-guard/windows-agent/agent.js');
const { ManagedInstallGuard } = require('../desktop-guard/windows-agent/managed-install.js');
const { DirectoryWatcher } = require('../desktop-guard/windows-agent/directory-watcher.js');

function delay(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

(async () => {
  const root = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'malguard-win-agent-'));
  const game = path.join(root, 'game');
  const quarantine = path.join(root, 'quarantine');
  const staging = path.join(root, 'staging');
  await fs.promises.mkdir(game, { recursive: true });

  assert.equal(protocol.createAgentHello().agentVersion, '0.2.0');
  assert.deepEqual(protocol.validateCoreHello({protocolVersion:'1.0.0', guardContractVersion:'0.2.0'}), {ok:true});
  assert.equal(protocol.validateCoreHello({protocolVersion:'9.0.0', guardContractVersion:'0.2.0'}).ok, false);

  const store = new QuarantineStore(quarantine);
  const qFile = path.join(game, 'bad.lua');
  await fs.promises.writeFile(qFile, 'synthetic test content');
  const q = await store.quarantine(qFile, { verdict:'MALICIOUS', action:'block_and_quarantine', reason:'test' });
  assert.equal(fs.existsSync(qFile), false);
  assert.equal(fs.existsSync(q.quarantinedPath), true);
  const restored = await store.restore(q.id);
  assert.equal(restored.restored, true);
  assert.equal(fs.existsSync(qFile), true);

  const safeFile = path.join(game, 'safe.lua');
  await fs.promises.writeFile(safeFile, 'safe');
  const safeAgent = new WindowsUserSpaceGuardAgent({
    roots:[game], quarantineRoot:quarantine, scanner: async()=>({verdict:'SAFE', reasons:[]})
  });
  const safeResult = await safeAgent.processPath(safeFile);
  assert.equal(safeResult.action, 'release');
  assert.equal(fs.existsSync(safeFile), true);

  const maliciousFile = path.join(game, 'mod', 'evil.lua');
  await fs.promises.mkdir(path.dirname(maliciousFile), {recursive:true});
  await fs.promises.writeFile(maliciousFile, 'evil-test');
  const incidents = [];
  const badAgent = new WindowsUserSpaceGuardAgent({
    roots:[game], quarantineRoot:path.join(root, 'quarantine-2'),
    scanner: async()=>({verdict:'MALICIOUS', reasons:['synthetic_rule']}),
    onIncident: async report => incidents.push(report),
  });
  const badResult = await badAgent.processPath(maliciousFile);
  assert.equal(badResult.action, 'block_and_quarantine');
  assert.equal(fs.existsSync(maliciousFile), false);
  assert.equal(incidents.length, 1);
  assert.equal(incidents[0].responsibleFile, 'evil.lua');

  const changingFile = path.join(game, 'changing.lua');
  await fs.promises.writeFile(changingFile, 'v1');
  const changingAgent = new WindowsUserSpaceGuardAgent({
    roots:[game], quarantineRoot:path.join(root, 'quarantine-3'),
    scanner: async file => {
      await fs.promises.writeFile(file, 'v2-mutated-during-scan');
      return {verdict:'SAFE', reasons:[]};
    },
  });
  const changingResult = await changingAgent.processPath(changingFile);
  assert.equal(changingResult.verdict, 'INCONCLUSIVE');
  assert.equal(changingResult.action, 'hold');
  assert.equal(fs.existsSync(changingFile), false);

  const sourceSafe = path.join(root, 'download-safe.lua');
  await fs.promises.writeFile(sourceSafe, 'safe managed install');
  const installStore = new QuarantineStore(path.join(root, 'quarantine-install'));
  const installer = new ManagedInstallGuard({
    gameRoots:[game], stagingRoot:staging, quarantineStore:installStore,
    scanner: async()=>({verdict:contract.VERDICTS.SAFE,reasons:[]}),
  });
  const destinationSafe = path.join(game, 'mods', 'installed.lua');
  const installed = await installer.install(sourceSafe, destinationSafe);
  assert.equal(installed.installed, true);
  assert.equal(fs.existsSync(destinationSafe), true);

  const sourceBad = path.join(root, 'download-bad.lua');
  await fs.promises.writeFile(sourceBad, 'bad managed install');
  const badInstaller = new ManagedInstallGuard({
    gameRoots:[game], stagingRoot:path.join(root,'staging-2'), quarantineStore:installStore,
    scanner: async()=>({verdict:contract.VERDICTS.MALICIOUS,reasons:['synthetic_rule']}),
  });
  const destinationBad = path.join(game, 'mods', 'blocked.lua');
  const blocked = await badInstaller.install(sourceBad, destinationBad);
  assert.equal(blocked.installed, false);
  assert.equal(blocked.action, 'block_and_quarantine');
  assert.equal(fs.existsSync(destinationBad), false);

  const watchRoot = path.join(root, 'watch');
  await fs.promises.mkdir(watchRoot, {recursive:true});
  const events = [];
  const watcher = new DirectoryWatcher({roots:[watchRoot], onEvent: async e => events.push(e), debounceMs:30});
  await watcher.start();
  const watchedFile = path.join(watchRoot, 'new.lua');
  await fs.promises.writeFile(watchedFile, 'watch me');
  for (let i=0; i<30 && !events.some(e=>e.path===path.resolve(watchedFile)); i++) await delay(50);
  await watcher.stop();
  assert.equal(events.some(e => e.path === path.resolve(watchedFile) && (e.type === 'file_created' || e.type === 'file_changed')), true, 'real filesystem watcher should observe file creation/change');


  // Existing active-code files must be scanned during watcher baseline, not only future changes.
  const baselineRoot = path.join(root, 'baseline');
  const baselineQuarantine = path.join(root, 'baseline-quarantine');
  await fs.promises.mkdir(baselineRoot, {recursive:true});
  const preexisting = path.join(baselineRoot, 'preexisting.lua');
  await fs.promises.writeFile(preexisting, 'preexisting malicious synthetic');
  const baselineAgent = new WindowsUserSpaceGuardAgent({
    roots:[baselineRoot], quarantineRoot:baselineQuarantine,
    scanner: async()=>({verdict:contract.VERDICTS.MALICIOUS,reasons:['baseline_synthetic']}),
  });
  const baselineStart = await baselineAgent.startWatching();
  assert.equal(baselineStart.active, true);
  assert.equal(fs.existsSync(preexisting), false, 'pre-existing protected file should be scanned/quarantined before start resolves');
  const baselineEntries = await baselineAgent.listQuarantine();
  assert.equal(baselineEntries.length, 1);
  await baselineAgent.stopWatching();

  // Non-active assets are ignored by the default real-time code protection filter.
  const asset = path.join(baselineRoot, 'texture.ytd');
  await fs.promises.writeFile(asset, 'asset');
  const ignored = await baselineAgent.processPath(asset);
  assert.equal(ignored.ignored, true);
  assert.equal(fs.existsSync(asset), true);

  // Quarantine IDs are strict UUIDs; path traversal through the restore API is rejected.
  await assert.rejects(() => store.restore('../escape'), err => err && err.code === 'INVALID_QUARANTINE_ID');

  // A tampered manifest cannot redirect the quarantine payload path or restore outside allowed roots.
  const guardedStore = new QuarantineStore(path.join(root, 'guarded-store'), { allowedRestoreRoots: [game] });
  const guardedFile = path.join(game, 'guarded.lua');
  await fs.promises.writeFile(guardedFile, 'guarded-content');
  const guardedEntry = await guardedStore.quarantine(guardedFile, { originalPath: guardedFile, verdict:'SUSPICIOUS', action:'quarantine' });
  const manifestPath = path.join(root, 'guarded-store', 'manifests', `${guardedEntry.id}.json`);
  const tampered = JSON.parse(await fs.promises.readFile(manifestPath, 'utf8'));
  tampered.quarantinedPath = path.join(root, 'unrelated-file');
  tampered.originalPath = path.join(root, 'outside-root.lua');
  await fs.promises.writeFile(manifestPath, JSON.stringify(tampered, null, 2));
  await assert.rejects(() => guardedStore.restore(guardedEntry.id), err => err && (err.code === 'PATH_OUTSIDE_ALLOWED_ROOTS' || err.code === 'PATH_OUTSIDE_ROOT'));

  await fs.promises.rm(root, { recursive: true, force: true });
  console.log('✓ Windows Guard v0.1 user-space agent: watch/quarantine/restore/revalidation/managed-install PASS');
})().catch(error => {
  console.error(error);
  process.exit(1);
});
