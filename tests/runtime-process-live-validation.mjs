import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { RuntimeGameProcessGuard } = require('../desktop-guard/windows-agent/runtime-process-guard.js');

if (process.platform !== 'win32') throw new Error('runtime process live validation requires Windows');
const fixture = process.env.MALGUARD_RUNTIME_CHILD_EXE;
if (!fixture || !fs.existsSync(fixture)) throw new Error('MALGUARD_RUNTIME_CHILD_EXE missing');

const root = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'malguard-runtime-live-'));
const game = path.join(root, 'game');
await fs.promises.mkdir(game, { recursive:true });
const gameExe = path.join(game, 'MalGuardSyntheticGame.exe');
await fs.promises.copyFile(fixture, gameExe);

function launch() {
  const child = spawn(gameExe, ['--sleep-ms', '30000'], { windowsHide:true, stdio:['ignore','pipe','pipe'] });
  return new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => { if (!settled) { settled = true; reject(new Error('synthetic child readiness timeout')); } }, 5000);
    child.once('error', error => { if (!settled) { settled = true; clearTimeout(timer); reject(error); } });
    child.stdout.on('data', chunk => {
      if (!settled && chunk.toString('utf8').includes('MALGUARD_RUNTIME_SYNTHETIC_READY')) {
        settled = true;
        clearTimeout(timer);
        resolve(child);
      }
    });
  });
}

function waitExit(child, timeoutMs = 5000) {
  if (child.exitCode !== null) return Promise.resolve(child.exitCode);
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('synthetic child did not exit')), timeoutMs);
    child.once('exit', code => { clearTimeout(timer); resolve(code); });
  });
}

let safeChild;
let blockedChild;
try {
  safeChild = await launch();
  const safe = new RuntimeGameProcessGuard({
    roots:[game], serviceMode:true, platform:'win32', intervalMs:60000,
    trustedPath:async()=>true,
    scanner:async()=>({verdict:'SAFE'}),
  });
  const safeStatus = await safe.start();
  assert.equal(safeStatus.ok, true, JSON.stringify(safeStatus));
  assert.equal(safeStatus.healthy, true);
  assert(safeStatus.monitoredProcesses >= 1, JSON.stringify(safeStatus));
  assert.equal(safeChild.exitCode, null, 'trusted synthetic game should remain running');
  await safe.stop();
  safeChild.kill();
  await waitExit(safeChild);

  blockedChild = await launch();
  const blocked = new RuntimeGameProcessGuard({
    roots:[game], serviceMode:true, platform:'win32', intervalMs:60000,
    trustedPath:async()=>false,
    scanner:async()=>({verdict:'SAFE'}),
  });
  const blockedStatus = await blocked.start();
  assert.equal(blockedStatus.ok, true, JSON.stringify(blockedStatus));
  assert.equal(blockedStatus.lastAction, 'terminated_game_process');
  await waitExit(blockedChild);
  assert.notEqual(blockedChild.exitCode, null, 'untrusted protected-root process should be terminated');
  await blocked.stop();

  console.log(JSON.stringify({
    ok:true,
    kind:'malguard-runtime-game-process-live-validation',
    safeProcessObserved:true,
    untrustedProcessTerminated:true,
    syntheticOnly:true,
    malwareDownloaded:false,
    memoryInjectionPerformed:false,
  }, null, 2));
  console.log('✓ Real Windows runtime game process protection live validation PASS');
} finally {
  try { if (safeChild && safeChild.exitCode === null) safeChild.kill(); } catch {}
  try { if (blockedChild && blockedChild.exitCode === null) blockedChild.kill(); } catch {}
  await fs.promises.rm(root, { recursive:true, force:true });
}
