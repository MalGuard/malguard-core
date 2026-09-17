'use strict';

const assert = require('assert');
const {
  createGameWorld,
  classifyBehavior,
  simulateBehavior,
} = require('../desktop-app/isolation/gamesim-isolation.js');

const world = createGameWorld();
assert.equal(world.hostExecution, false);
assert.equal(world.networkMode, 'simulated-no-egress');
assert.equal(world.persistence, 'ephemeral');
assert.ok(world.virtualProcesses.includes('GTA5.exe'));

const low = classifyBehavior([
  { type: 'game_file_modify', target: 'mods/example.asi', confidence: 0.8 },
]);
assert.equal(low.verdict, 'inconclusive');
assert.ok(low.risk < 30);

const high = classifyBehavior([
  { type: 'credential_access', target: 'synthetic-game-session-token', confidence: 1 },
  { type: 'persistence', target: 'virtual-registry', confidence: 1 },
  { type: 'network_connect', target: 'simulated-endpoint', confidence: 1 },
]);
assert.equal(high.verdict, 'malicious');
assert.ok(high.risk >= 70);

const result = simulateBehavior({
  filePath: 'C:/Samples/test.exe',
  staticEvidence: [
    { type: 'process_spawn', target: 'powershell.exe', confidence: 0.9 },
    { type: 'network_connect', target: 'simulated-endpoint', confidence: 0.7 },
  ],
});
assert.equal(result.ok, true);
assert.equal(result.engine, 'gamesim-isolation');
assert.equal(result.executionMode, 'behavioral-emulation');
assert.equal(result.realSampleExecuted, false);
assert.equal(result.hostExecution, false);
assert.equal(result.networkEgress, false);
assert.equal(result.ephemeral, true);
assert.notEqual(result.verdict, 'safe');

console.log('✓ GameSim isolation: virtual game world, no host execution, no egress and fail-closed verdict semantics PASS');
