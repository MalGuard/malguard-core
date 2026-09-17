'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const PROFILE_VERSION = '1.0.0';
const DEFAULT_GAME_ID = 'generic-moddable-game';

function sha256File(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function safeName(value) {
  const base = path.basename(String(value || 'sample.bin')).replace(/[^A-Za-z0-9._-]/g, '_');
  return base || 'sample.bin';
}

function createGameEnvironment(samplePath, { gameId = DEFAULT_GAME_ID, tempRoot = os.tmpdir() } = {}) {
  const resolved = path.resolve(samplePath || '');
  const stat = fs.lstatSync(resolved);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size <= 0) {
    const error = new Error('sample must be a non-empty regular file');
    error.code = 'ISOLATION_SAMPLE_INVALID';
    throw error;
  }

  const root = fs.mkdtempSync(path.join(tempRoot, 'malguard-isolation-'));
  const gameRoot = path.join(root, 'Game');
  const modsRoot = path.join(gameRoot, 'mods');
  const pluginsRoot = path.join(gameRoot, 'plugins');
  const scriptsRoot = path.join(gameRoot, 'scripts');
  const savesRoot = path.join(gameRoot, 'saves');
  const outputRoot = path.join(root, 'telemetry');
  for (const dir of [gameRoot, modsRoot, pluginsRoot, scriptsRoot, savesRoot, outputRoot]) fs.mkdirSync(dir, { recursive: true });

  const sampleName = safeName(resolved);
  const isolatedSamplePath = path.join(modsRoot, sampleName);
  fs.copyFileSync(resolved, isolatedSamplePath, fs.constants.COPYFILE_EXCL);

  const profile = {
    schemaVersion: PROFILE_VERSION,
    product: 'MalGuard Isolation',
    gameId,
    simulated: true,
    hostGameFilesExposed: false,
    networkAllowed: false,
    sample: {
      name: sampleName,
      size: stat.size,
      sha256: sha256File(resolved),
      relativePath: `Game/mods/${sampleName}`,
    },
    layout: {
      gameRoot: 'Game',
      mods: 'Game/mods',
      plugins: 'Game/plugins',
      scripts: 'Game/scripts',
      saves: 'Game/saves',
      telemetry: 'telemetry',
    },
  };
  fs.writeFileSync(path.join(root, 'game-profile.json'), JSON.stringify(profile, null, 2) + '\n', { flag: 'wx' });

  return {
    root,
    gameRoot,
    modsRoot,
    pluginsRoot,
    scriptsRoot,
    savesRoot,
    outputRoot,
    isolatedSamplePath,
    profile,
    cleanup() { fs.rmSync(root, { recursive: true, force: true }); },
  };
}

module.exports = { PROFILE_VERSION, DEFAULT_GAME_ID, createGameEnvironment };
