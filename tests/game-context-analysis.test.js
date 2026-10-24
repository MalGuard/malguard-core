'use strict';

const assert = require('assert');
const { behaviorDiff, buildCausalityMap, comparativeVerdict } = require('../desktop-app/sandbox/game-context-analysis.js');

const neutral = {
  execution: { started: true, timedOut: false },
  baselineProcesses: [{ id: 10, processName: 'explorer', path: 'C:/Windows/explorer.exe' }],
  finalProcesses: [
    { id: 10, processName: 'explorer', path: 'C:/Windows/explorer.exe' },
    { id: 20, processName: 'sample', path: 'C:/MalGuardInput/sample.exe' },
  ],
  recentFiles: [
    { fullName: 'C:/Users/WDAGUtilityAccount/AppData/Local/Temp/sample.log', length: 4, lastWriteTimeUtc: '2026-09-16T00:00:00.000Z' },
  ],
};

const game = {
  execution: { started: true, timedOut: false },
  baselineProcesses: [
    { id: 10, processName: 'explorer', path: 'C:/Windows/explorer.exe' },
    { id: 30, processName: 'GTA5', path: 'C:/MalGuardGame/GTA5.exe' },
  ],
  finalProcesses: [
    { id: 10, processName: 'explorer', path: 'C:/Windows/explorer.exe' },
    { id: 30, processName: 'GTA5', path: 'C:/MalGuardGame/GTA5.exe' },
    { id: 21, processName: 'sample', path: 'C:/MalGuardInput/sample.exe' },
    { id: 40, processName: 'helper', path: 'C:/Users/WDAGUtilityAccount/AppData/Local/Temp/helper.exe' },
  ],
  recentFiles: [
    { fullName: 'C:/Users/WDAGUtilityAccount/AppData/Local/Temp/sample.log', length: 4, lastWriteTimeUtc: '2026-09-16T00:00:00.000Z' },
    { fullName: 'C:/Users/WDAGUtilityAccount/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/loader.cmd', length: 8, lastWriteTimeUtc: '2026-09-16T00:00:01.000Z' },
  ],
  gameContext: {
    enabled: true,
    fixtureStarted: true,
    processId: 30,
    processName: 'GTA5',
    baselineModules: [
      { moduleName: 'kernel32.dll', fileName: 'C:/Windows/System32/kernel32.dll' },
    ],
    finalModules: [
      { moduleName: 'kernel32.dll', fileName: 'C:/Windows/System32/kernel32.dll' },
      { moduleName: 'unexpected.dll', fileName: 'C:/Users/WDAGUtilityAccount/AppData/Local/Temp/unexpected.dll' },
    ],
  },
};

const diff = behaviorDiff(neutral, game);
assert.equal(diff.verdict, 'suspicious');
assert(diff.signals.includes('game_process_new_module'));
assert(diff.signals.includes('game_context_persistence_artifact'));
assert.equal(diff.newGameModules.length, 1);
assert.equal(diff.persistenceLikeFiles.length, 1);
assert.equal(diff.gameSpecificProcesses.length, 1);

const map = buildCausalityMap({ neutralTelemetry: neutral, gameTelemetry: game, diff });
assert(map.nodes.some(n => n.id === 'game_process'));
assert(map.nodes.some(n => n.id === 'module_delta'));
assert(map.nodes.some(n => n.id === 'persistence_artifact'));
assert(map.edges.some(e => e.relation === 'module_set_changed_after_sample_execution' && e.confidence === 'observed'));
assert(map.limits.some(v => /does not by itself prove process injection/i.test(v)));

assert.equal(comparativeVerdict({
  neutralAssessment: { verdict: 'inconclusive' },
  gameAssessment: { verdict: 'inconclusive' },
  diff,
}), 'suspicious');

console.log('✓ Game-context causality: behavior diff, module delta, persistence artifact and evidence-qualified causality PASS');
