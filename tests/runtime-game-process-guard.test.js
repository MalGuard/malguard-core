'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { RuntimeGameProcessGuard } = require('../desktop-guard/windows-agent/runtime-process-guard.js');

(async () => {
  const temp = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'malguard-runtime-game-'));
  const game = path.join(temp, 'game');
  const outside = path.join(temp, 'outside');
  await fs.promises.mkdir(game, { recursive:true });
  await fs.promises.mkdir(outside, { recursive:true });
  const gameExe = path.join(game, 'game.exe');
  const trustedDll = path.join(game, 'trusted.dll');
  const untrustedDll = path.join(game, 'untrusted.dll');
  const externalDll = path.join(outside, 'external.dll');
  for (const [file, text] of [[gameExe,'game'],[trustedDll,'trusted'],[untrustedDll,'untrusted'],[externalDll,'external']]) await fs.promises.writeFile(file, text);

  const baseSnapshot = {
    ok:true,
    truncated:false,
    processes:[{ pid:4242, name:'game', path:gameExe, moduleEnumerationOk:true, modules:[gameExe, trustedDll] }],
  };

  const trusted = new Set([path.resolve(gameExe), path.resolve(trustedDll)]);
  const guard = new RuntimeGameProcessGuard({
    roots:[game], platform:'win32', serviceMode:true, intervalMs:60000,
    scanner:async()=>({verdict:'SAFE'}),
    trustedPath:async file=>trusted.has(path.resolve(file)),
    snapshotProvider:async()=>baseSnapshot,
    terminateProcess:async()=>({ok:true,terminated:true}),
  });
  const caps = guard.capabilities();
  assert.equal(caps.moduleLoadProtection, true);
  assert.equal(caps.memoryOnlyInjectionProtection, false);
  assert.match(caps.threatModel, /does not claim kernel or memory-only injection coverage/i);
  const started = await guard.start();
  assert.equal(started.ok, true);
  assert.equal(started.healthy, true);
  assert.equal(started.monitoredProcesses, 1);
  await guard.stop();

  // A code module loaded from the protected game root must match the identity
  // previously released by the folder scanner. Unknown root code is fail-closed.
  const terminations = [];
  const incidents = [];
  const rootViolation = new RuntimeGameProcessGuard({
    roots:[game], platform:'win32', serviceMode:true, intervalMs:60000,
    scanner:async()=>({verdict:'SAFE'}),
    trustedPath:async file=>path.resolve(file) !== path.resolve(untrustedDll),
    snapshotProvider:async()=>({ ok:true, truncated:false, processes:[{ pid:55, name:'game', path:gameExe, moduleEnumerationOk:true, modules:[gameExe, untrustedDll] }] }),
    terminateProcess:async(pid, expectedPath)=>{ terminations.push({pid,expectedPath}); return {ok:true,terminated:true}; },
    onIncident:async report=>incidents.push(report),
  });
  const rootResult = await rootViolation.start();
  assert.equal(rootResult.ok, true);
  assert.equal(terminations.length, 1);
  assert.equal(terminations[0].pid, 55);
  assert.equal(incidents.length, 1);
  assert.equal(incidents[0].action, 'terminate_game_process');
  assert.match(incidents[0].reason, /trusted identity/i);
  await rootViolation.stop();

  // Executable modules injected from outside protected/system program locations
  // are scanned at runtime. Anything other than SAFE is terminated fail-closed.
  let externalScans = 0;
  const externalTerms = [];
  const externalGuard = new RuntimeGameProcessGuard({
    roots:[game], platform:'win32', serviceMode:true, intervalMs:60000,
    trustedPath:async()=>true,
    scanner:async file=>{ externalScans++; assert.equal(path.resolve(file), path.resolve(externalDll)); return {verdict:'MALICIOUS'}; },
    snapshotProvider:async()=>({ ok:true, truncated:false, processes:[{ pid:77, name:'game', path:gameExe, moduleEnumerationOk:true, modules:[gameExe, trustedDll, externalDll] }] }),
    terminateProcess:async(pid)=>{ externalTerms.push(pid); return {ok:true,terminated:true}; },
  });
  const externalResult = await externalGuard.start();
  assert.equal(externalResult.ok, true);
  assert.equal(externalScans, 1);
  assert.deepEqual(externalTerms, [77]);
  await externalGuard.stop();

  // SAFE external modules are identity-cached so polling does not rescan the same
  // unchanged overlay/module forever.
  let safeScans = 0;
  const safeExternal = new RuntimeGameProcessGuard({
    roots:[game], platform:'win32', serviceMode:true, intervalMs:60000,
    trustedPath:async()=>true,
    scanner:async()=>{ safeScans++; return {verdict:'SAFE'}; },
    snapshotProvider:async()=>({ ok:true, truncated:false, processes:[{ pid:88, name:'game', path:gameExe, moduleEnumerationOk:true, modules:[gameExe, externalDll] }] }),
    terminateProcess:async()=>{ throw new Error('safe external module must not terminate process'); },
  });
  await safeExternal.start();
  await safeExternal.poll();
  assert.equal(safeScans, 1);
  await safeExternal.stop();

  // If module enumeration itself cannot be trusted, complete runtime protection
  // degrades instead of pretending the process was inspected.
  const weak = new RuntimeGameProcessGuard({
    roots:[game], platform:'win32', serviceMode:true,
    trustedPath:async()=>true,
    scanner:async()=>({verdict:'SAFE'}),
    snapshotProvider:async()=>({ ok:true, truncated:false, processes:[{ pid:99, name:'game', path:gameExe, moduleEnumerationOk:false, modules:[] }] }),
    terminateProcess:async()=>({ok:true,terminated:true}),
  });
  const weakResult = await weak.start();
  assert.equal(weakResult.ok, false);
  assert.equal(weakResult.healthy, false);
  assert.equal(weakResult.reason, 'RUNTIME_MODULE_ENUMERATION_FAILED');

  const unsupported = new RuntimeGameProcessGuard({ roots:[game], platform:'linux', serviceMode:true, trustedPath:async()=>true, scanner:async()=>({verdict:'SAFE'}), snapshotProvider:async()=>baseSnapshot, terminateProcess:async()=>({ok:true,terminated:true}) });
  assert.equal((await unsupported.start()).reason, 'RUNTIME_PROCESS_WINDOWS_REQUIRED');
  const direct = new RuntimeGameProcessGuard({ roots:[game], platform:'win32', serviceMode:false, trustedPath:async()=>true, scanner:async()=>({verdict:'SAFE'}), snapshotProvider:async()=>baseSnapshot, terminateProcess:async()=>({ok:true,terminated:true}) });
  assert.equal((await direct.start()).reason, 'RUNTIME_PROCESS_SERVICE_REQUIRED');

  const helper = await fs.promises.readFile(path.join(__dirname, '..', 'desktop-guard', 'windows-agent', 'windows-tools', 'runtime-process-helper.ps1'), 'utf8');
  assert.match(helper, /Get-Process/);
  assert.match(helper, /\.Modules/);
  assert.match(helper, /Stop-Process/);
  assert.doesNotMatch(helper, /WriteProcessMemory|CreateRemoteThread|VirtualAllocEx/i);

  await fs.promises.rm(temp, { recursive:true, force:true });
  console.log('✓ Runtime game process protection: trusted module identity, external module scan, fail-closed termination and honest coverage boundary PASS');
})().catch(error => { console.error(error.stack || error); process.exit(1); });
