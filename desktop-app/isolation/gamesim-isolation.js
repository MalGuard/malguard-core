'use strict';

const path = require('path');

const ENGINE_VERSION = '0.1.0';

const DEFAULT_GAME_WORLD = Object.freeze({
  game: 'GTA V',
  launcher: 'Rockstar Games Launcher',
  platform: 'Windows-like simulated guest',
  networkMode: 'simulated-no-egress',
  persistence: 'ephemeral',
  hostExecution: false,
  virtualProcesses: [
    'GTA5.exe',
    'PlayGTAV.exe',
    'RockstarService.exe',
    'steam.exe',
    'Discord.exe',
  ],
  virtualPaths: [
    'C:/Program Files/Rockstar Games/Grand Theft Auto V',
    'C:/Users/Player/Documents/Rockstar Games/GTA V',
    'C:/Users/Player/AppData/Local/Temp',
    'C:/Users/Player/AppData/Roaming',
  ],
  decoys: [
    'synthetic-game-session-token',
    'synthetic-launcher-session',
    'synthetic-wallet-placeholder',
  ],
});

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function createGameWorld(overrides = {}) {
  return Object.freeze({
    ...clone(DEFAULT_GAME_WORLD),
    ...clone(overrides),
    hostExecution: false,
    networkMode: 'simulated-no-egress',
    persistence: 'ephemeral',
  });
}

function normalizeEvidence(evidence) {
  const out = [];
  if (!evidence) return out;
  const values = Array.isArray(evidence) ? evidence : [evidence];
  for (const item of values) {
    if (!item || typeof item !== 'object') continue;
    const type = String(item.type || '').trim().toLowerCase();
    if (!type) continue;
    out.push({
      type,
      target: item.target == null ? null : String(item.target),
      detail: item.detail == null ? null : String(item.detail),
      confidence: Number.isFinite(Number(item.confidence)) ? Math.max(0, Math.min(1, Number(item.confidence))) : 0.5,
    });
  }
  return out;
}

function classifyBehavior(evidence) {
  const signals = [];
  let risk = 0;
  for (const item of normalizeEvidence(evidence)) {
    const type = item.type;
    let weight = 0;
    if (['credential_access', 'token_access', 'wallet_access'].includes(type)) weight = 35;
    else if (['persistence', 'registry_autorun', 'scheduled_task'].includes(type)) weight = 25;
    else if (['process_spawn', 'process_injection_attempt'].includes(type)) weight = 20;
    else if (['file_write', 'file_delete', 'archive_drop'].includes(type)) weight = 12;
    else if (['network_connect', 'dns_request', 'http_request'].includes(type)) weight = 10;
    else if (['game_file_modify', 'mod_install'].includes(type)) weight = 5;
    if (weight <= 0) continue;
    const score = Math.round(weight * item.confidence);
    risk += score;
    signals.push({ ...item, score });
  }
  risk = Math.min(100, risk);
  let verdict = 'inconclusive';
  if (risk >= 70) verdict = 'malicious';
  else if (risk >= 30) verdict = 'suspicious';
  else if (signals.length > 0) verdict = 'inconclusive';
  return { risk, verdict, signals };
}

function simulateBehavior({ filePath, staticEvidence = [], world = null } = {}) {
  if (typeof filePath !== 'string' || !filePath.trim()) {
    const error = new Error('GameSim filePath is required');
    error.code = 'GAMESIM_PATH_REQUIRED';
    throw error;
  }
  const gameWorld = world ? createGameWorld(world) : createGameWorld();
  const behavior = classifyBehavior(staticEvidence);
  return {
    ok: true,
    engine: 'gamesim-isolation',
    engineVersion: ENGINE_VERSION,
    executionMode: 'behavioral-emulation',
    realSampleExecuted: false,
    hostExecution: false,
    networkEgress: false,
    ephemeral: true,
    sample: {
      name: path.basename(filePath),
      extension: path.extname(filePath).toLowerCase(),
    },
    world: gameWorld,
    telemetry: {
      simulatedProcesses: gameWorld.virtualProcesses.length,
      simulatedPaths: gameWorld.virtualPaths.length,
      decoyCount: gameWorld.decoys.length,
      signals: behavior.signals,
    },
    riskScore: behavior.risk,
    verdict: behavior.verdict,
    limitations: [
      'No native Windows instruction execution in GameSim v0.1',
      'Behavior is emulated from trusted parser/static-analysis evidence',
      'A clean GameSim result must not be upgraded to SAFE without stronger evidence',
    ],
  };
}

module.exports = {
  ENGINE_VERSION,
  DEFAULT_GAME_WORLD,
  createGameWorld,
  normalizeEvidence,
  classifyBehavior,
  simulateBehavior,
};
