'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const contract = require('../desktop-guard/guard-contract.js');
const { WindowsUserSpaceGuardAgent } = require('../desktop-guard/windows-agent/agent.js');
const { IncidentStore } = require('../desktop-guard/windows-agent/incident-store.js');

(async () => {
  const root = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'malguard-runtime-containment-'));
  const game = path.join(root, 'game');
  const quarantine = path.join(root, 'quarantine');
  await fs.promises.mkdir(game, { recursive: true });

  // The protected file must already be absent from the game tree when the
  // expensive scanner callback begins.
  const heldSafe = path.join(game, 'held-safe.lua');
  await fs.promises.writeFile(heldSafe, 'safe synthetic');
  let scannerSawOriginal = null;
  let scannerSawHeld = null;
  const agent = new WindowsUserSpaceGuardAgent({
    roots: [game],
    quarantineRoot: quarantine,
    scanner: async scanPath => {
      scannerSawOriginal = fs.existsSync(heldSafe);
      scannerSawHeld = fs.existsSync(scanPath);
      return { verdict: contract.VERDICTS.SAFE, reasons: [] };
    },
  });
  const safeResult = await agent.processPath(heldSafe);
  assert.equal(scannerSawOriginal, false, 'original game path must be held before scanner starts');
  assert.equal(scannerSawHeld, true, 'scanner must receive the held payload');
  assert.equal(safeResult.preScanHeld, true);
  assert.equal(fs.existsSync(heldSafe), true, 'SAFE held file should be released back to the game root');

  // Duplicate watcher-style processing of the exact released identity should
  // not needlessly rescan it.
  let duplicateScans = 0;
  agent.scanner = async () => { duplicateScans++; return { verdict: contract.VERDICTS.SAFE, reasons: [] }; };
  const duplicate = await agent.processPath(heldSafe);
  assert.equal(duplicate.trustedIdentityHit, true);
  assert.equal(duplicateScans, 0);

  // A same-path mutation invalidates the trust cache and is held/scanned again.
  await fs.promises.writeFile(heldSafe, 'mutated after trusted release');
  agent.scanner = async scanPath => {
    duplicateScans++;
    assert.equal(fs.existsSync(heldSafe), false);
    assert.equal(fs.existsSync(scanPath), true);
    return { verdict: contract.VERDICTS.MALICIOUS, reasons: ['synthetic_mutation'] };
  };
  const mutated = await agent.processPath(heldSafe);
  assert.equal(mutated.action, contract.ACTIONS.BLOCK_AND_QUARANTINE);
  assert.equal(fs.existsSync(heldSafe), false);
  assert.equal(duplicateScans, 1);

  // Persistent incidents survive process-memory loss and tolerate a corrupt
  // historical line without losing later valid records.
  const incidentStore = new IncidentStore(quarantine);
  await incidentStore.append({
    schemaVersion: '1.0.0', incidentId: 'incident-a', modName: 'Synthetic', responsibleFile: 'held-safe.lua',
    verdict: 'MALICIOUS', reason: 'synthetic', action: 'block_and_quarantine', timestamp: Date.now(), source: 'test',
  });
  await fs.promises.appendFile(incidentStore.eventsFile, '{torn-json\n');
  await incidentStore.append({
    schemaVersion: '1.0.0', incidentId: 'incident-b', modName: 'Synthetic', responsibleFile: 'second.lua',
    verdict: 'SUSPICIOUS', reason: 'synthetic2', action: 'quarantine', timestamp: Date.now() + 1, source: 'test',
  });
  const rows = await incidentStore.list(10);
  assert.equal(rows[0].incidentId, 'incident-b');
  assert.equal(rows.some(row => row.incidentId === 'incident-a'), true);

  await fs.promises.rm(root, { recursive: true, force: true });
  console.log('✓ Runtime containment: pre-scan hold, trust revalidation and persistent incident journal PASS');
})().catch(error => {
  console.error(error.stack || error);
  process.exit(1);
});
