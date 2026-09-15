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
    processes:[{
      pid:4242, name:'game', path:gameExe,
      moduleEnumerationOk:true, modules:[gameExe, trustedDll],
      threadEnumerationOk:true, threadCount:4, unbackedThreadCount:0,
    }],
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
  assert.equal(caps.threadStartTelemetry, true);
  assert.equal(caps.unbackedThreadProtection, true);
  assert.equal(caps.memoryOnlyInjectionHeuristicDetection, true);
  assert.equal(caps.memoryOnlyInjectionProtection, false);
  assert.match(caps.threatModel, /does not claim complete kernel or memory-only injection prevention/i);
  const started = await guard.start();
  assert.equal(started.ok, true);
  assert.equal(started.healthy, true);
  assert.equal(started.monitoredProcesses, 1);
  await guard.stop();

  const terminations = [];
  const incidents = [];
  const rootViolation = new RuntimeGameProcessGuard({
    roots:[game], platform:'win32', serviceMode:true, intervalMs:60000,
    scanner:async()=>({verdict:'SAFE'}),
    trustedPath:async file=>path.resolve(file) !== path.resolve(untrustedDll),
    snapshotProvider:async()=>({ ok:true, truncated:false, processes:[{
      pid:55, name:'game', path:gameExe,
      moduleEnumerationOk:true, modules:[gameExe, untrustedDll],
      threadEnumerationOk:true, threadCount:3, unbackedThreadCount:0,
    }] }),
    terminateProcess:async(pid, expectedPath)=>{ terminations.push({pid,expectedPath}); return {ok:true,terminated:true}; },
    onIncident:async report=>incidents.push(report),
  });
  const rootResult = await rootViolation.start();
  assert.equal(rootResult.ok, true);
  assert.equal(terminations.length, 1);
  assert.equal(terminations[0].pid, 55);
  assert.equal(incidents.length, 1);
  assert.equal(incidents[0].action, 'terminate_game_process');
  await rootViolation.stop();

  let externalScans = 0;
  const externalTerms = [];
  const externalGuard = new RuntimeGameProcessGuard({
    roots:[game], platform:'win32', serviceMode:true, intervalMs:60000,
    trustedPath:async()=>true,
    scanner:async file=>{ externalScans++; assert.equal(path.resolve(file), path.resolve(externalDll)); return {verdict:'MALICIOUS'}; },
    snapshotProvider:async()=>({ ok:true, truncated:false, processes:[{
      pid:77, name:'game', path:gameExe,
      moduleEnumerationOk:true, modules:[gameExe, trustedDll, externalDll],
      threadEnumerationOk:true, threadCount:5, unbackedThreadCount:0,
    }] }),
    terminateProcess:async(pid)=>{ externalTerms.push(pid); return {ok:true,terminated:true}; },
  });
  const externalResult = await externalGuard.start();
  assert.equal(externalResult.ok, true);
  assert.equal(externalScans, 1);
  assert.deepEqual(externalTerms, [77]);
  await externalGuard.stop();

  const threadTerms = [];
  const threadIncidents = [];
  const threadAnomaly = new RuntimeGameProcessGuard({
    roots:[game], platform:'win32', serviceMode:true, intervalMs:60000,
    trustedPath:async()=>true,
    scanner:async()=>({verdict:'SAFE'}),
    snapshotProvider:async()=>({ ok:true, truncated:false, processes:[{
      pid:78, name:'game', path:gameExe,
      moduleEnumerationOk:true, modules:[gameExe, trustedDll],
      threadEnumerationOk:true, threadCount:6, unbackedThreadCount:1,
    }] }),
    terminateProcess:async(pid)=>{ threadTerms.push(pid); return {ok:true,terminated:true}; },
    onIncident:async report=>threadIncidents.push(report),
  });
  const threadResult = await threadAnomaly.start();
  assert.equal(threadResult.ok, true);
  assert.deepEqual(threadTerms, [78]);
  assert.equal(threadIncidents.length, 1);
  assert.equal(threadIncidents[0].verdict, 'SUSPICIOUS');
  assert.match(threadIncidents[0].reason, /thread start address outside loaded module images/i);
  await threadAnomaly.stop();

  let safeScans = 0;
  const safeExternal = new RuntimeGameProcessGuard({
    roots:[game], platform:'win32', serviceMode:true, intervalMs:60000,
    trustedPath:async()=>true,
    scanner:async()=>{ safeScans++; return {verdict:'SAFE'}; },
    snapshotProvider:async()=>({ ok:true, truncated:false, processes:[{
      pid:88, name:'game', path:gameExe,
      moduleEnumerationOk:true, modules:[gameExe, externalDll],
      threadEnumerationOk:true, threadCount:2, unbackedThreadCount:0,
    }] }),
    terminateProcess:async()=>{ throw new Error('safe external module must not terminate process'); },
  });
  await safeExternal.start();
  await safeExternal.poll();
  assert.equal(safeScans, 1);
  await safeExternal.stop();

  const weak = new RuntimeGameProcessGuard({
    roots:[game], platform:'win32', serviceMode:true,
    trustedPath:async()=>true,
    scanner:async()=>({verdict:'SAFE'}),
    snapshotProvider:async()=>({ ok:true, truncated:false, processes:[{
      pid:99, name:'game', path:gameExe,
      moduleEnumerationOk:false, modules:[],
      threadEnumerationOk:false, threadCount:0, unbackedThreadCount:0,
    }] }),
    terminateProcess:async()=>({ok:true,terminated:true}),
  });
  const weakResult = await weak.start();
  assert.equal(weakResult.ok, false);
  assert.equal(weakResult.healthy, false);
  assert.equal(weakResult.reason, 'RUNTIME_MODULE_ENUMERATION_FAILED');

  const weakThreads = new RuntimeGameProcessGuard({
    roots:[game], platform:'win32', serviceMode:true,
    trustedPath:async()=>true,
    scanner:async()=>({verdict:'SAFE'}),
    snapshotProvider:async()=>({ ok:true, truncated:false, processes:[{
      pid:100, name:'game', path:gameExe,
      moduleEnumerationOk:true, modules:[gameExe],
      threadEnumerationOk:false, threadCount:0, unbackedThreadCount:0,
    }] }),
    terminateProcess:async()=>({ok:true,terminated:true}),
  });
  const weakThreadResult = await weakThreads.start();
  assert.equal(weakThreadResult.ok, false);
  assert.equal(weakThreadResult.healthy, false);
  assert.equal(weakThreadResult.reason, 'RUNTIME_THREAD_TELEMETRY_FAILED');

  const unsupported = new RuntimeGameProcessGuard({ roots:[game], platform:'linux', serviceMode:true, trustedPath:async()=>true, scanner:async()=>({verdict:'SAFE'}), snapshotProvider:async()=>baseSnapshot, terminateProcess:async()=>({ok:true,terminated:true}) });
  assert.equal((await unsupported.start()).reason, 'RUNTIME_PROCESS_WINDOWS_REQUIRED');
  const direct = new RuntimeGameProcessGuard({ roots:[game], platform:'win32', serviceMode:false, trustedPath:async()=>true, scanner:async()=>({verdict:'SAFE'}), snapshotProvider:async()=>baseSnapshot, terminateProcess:async()=>({ok:true,terminated:true}) });
  assert.equal((await direct.start()).reason, 'RUNTIME_PROCESS_SERVICE_REQUIRED');

  const helper = await fs.promises.readFile(path.join(__dirname, '..', 'desktop-guard', 'windows-agent', 'windows-tools', 'runtime-process-helper.ps1'), 'utf8');
  assert.match(helper, /Get-Process/);
  assert.match(helper, /\.Modules/);
  assert.match(helper, /\.Threads/);
  assert.match(helper, /StartAddress/);
  assert.match(helper, /Stop-Process/);

  await fs.promises.rm(temp, { recursive:true, force:true });
  console.log('✓ Runtime game process protection: module identity, external scan, thread telemetry and fail-closed response PASS');
})().catch(error => { console.error(error.stack || error); process.exit(1); });
