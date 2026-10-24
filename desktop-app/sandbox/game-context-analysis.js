'use strict';

const ANALYSIS_VERSION = '1.0.0';

function keyProcess(row) {
  if (!row || typeof row !== 'object') return null;
  const name = String(row.processName || row.ProcessName || '').trim().toLowerCase();
  const procPath = String(row.path || row.Path || '').trim().toLowerCase();
  return name ? `${name}|${procPath}` : null;
}

function keyFile(row) {
  if (!row || typeof row !== 'object') return null;
  const fullName = String(row.fullName || row.FullName || '').trim().toLowerCase();
  return fullName || null;
}

function spawnedProcesses(telemetry) {
  const baseline = new Set((telemetry && telemetry.baselineProcesses || []).map(p => Number(p.id ?? p.Id)));
  return (telemetry && telemetry.finalProcesses || []).filter(p => !baseline.has(Number(p.id ?? p.Id)));
}

function setDifference(rows, keyFn, referenceRows) {
  const reference = new Set((referenceRows || []).map(keyFn).filter(Boolean));
  return (rows || []).filter(row => {
    const key = keyFn(row);
    return key && !reference.has(key);
  });
}

function moduleKey(row) {
  if (!row || typeof row !== 'object') return null;
  const name = String(row.moduleName || row.ModuleName || '').trim().toLowerCase();
  const fileName = String(row.fileName || row.FileName || '').trim().toLowerCase();
  return name ? `${name}|${fileName}` : null;
}

function behaviorDiff(neutralTelemetry, gameTelemetry) {
  const neutralSpawned = spawnedProcesses(neutralTelemetry);
  const gameSpawned = spawnedProcesses(gameTelemetry);
  const neutralFiles = neutralTelemetry && neutralTelemetry.recentFiles || [];
  const gameFiles = gameTelemetry && gameTelemetry.recentFiles || [];
  const context = gameTelemetry && gameTelemetry.gameContext || null;
  const baselineModules = context && Array.isArray(context.baselineModules) ? context.baselineModules : [];
  const finalModules = context && Array.isArray(context.finalModules) ? context.finalModules : [];

  const gameSpecificProcesses = setDifference(gameSpawned, keyProcess, neutralSpawned);
  const gameSpecificFiles = setDifference(gameFiles, keyFile, neutralFiles);
  const newGameModules = setDifference(finalModules, moduleKey, baselineModules);
  const persistenceLikeFiles = gameSpecificFiles.filter(row => {
    const p = keyFile(row) || '';
    return p.includes('\\startup\\') || p.includes('/startup/') || p.includes('start menu\\programs\\startup');
  });

  const neutralExecution = neutralTelemetry && neutralTelemetry.execution || {};
  const gameExecution = gameTelemetry && gameTelemetry.execution || {};
  const gameOnlyTimeout = gameExecution.timedOut === true && neutralExecution.timedOut !== true;

  let riskScore = 0;
  const signals = [];
  if (newGameModules.length) { signals.push('game_process_new_module'); riskScore += 45; }
  if (persistenceLikeFiles.length) { signals.push('game_context_persistence_artifact'); riskScore += 35; }
  if (gameSpecificProcesses.length >= 3) { signals.push('game_context_process_fanout'); riskScore += 20; }
  else if (gameSpecificProcesses.length) { signals.push('game_context_process_delta'); riskScore += 10; }
  if (gameSpecificFiles.length >= 20) { signals.push('game_context_file_delta'); riskScore += 15; }
  if (gameOnlyTimeout) { signals.push('game_context_only_timeout'); riskScore += 15; }

  return {
    version: ANALYSIS_VERSION,
    riskScore: Math.min(100, riskScore),
    verdict: riskScore >= 25 ? 'suspicious' : 'inconclusive',
    signals,
    gameSpecificProcesses,
    gameSpecificFiles,
    newGameModules,
    persistenceLikeFiles,
    gameOnlyTimeout,
  };
}

function buildCausalityMap({ neutralTelemetry, gameTelemetry, diff }) {
  const nodes = [];
  const edges = [];
  const addNode = (id, type, label, evidence) => {
    if (!nodes.some(n => n.id === id)) nodes.push({ id, type, label, evidence });
  };
  const addEdge = (from, to, relation, confidence) => edges.push({ from, to, relation, confidence });

  addNode('sample_execution', 'execution', 'Sample executed in isolated environment', {
    neutralStarted: neutralTelemetry && neutralTelemetry.execution && neutralTelemetry.execution.started === true,
    gameStarted: gameTelemetry && gameTelemetry.execution && gameTelemetry.execution.started === true,
  });

  const ctx = gameTelemetry && gameTelemetry.gameContext;
  if (ctx && ctx.fixtureStarted === true) {
    addNode('game_process', 'environment', `Synthetic game process: ${ctx.processName || 'game fixture'}`, {
      processId: ctx.processId || null,
      fixtureStarted: true,
    });
    addEdge('sample_execution', 'game_process', 'coexisted_with', 'observed');
  }

  if (diff.newGameModules.length) {
    addNode('module_delta', 'module', 'New module appeared in synthetic game process', {
      modules: diff.newGameModules,
    });
    addEdge('game_process', 'module_delta', 'module_set_changed_after_sample_execution', 'observed');
  }

  if (diff.gameSpecificProcesses.length) {
    addNode('process_delta', 'process', 'Game-context-specific process activity', {
      processes: diff.gameSpecificProcesses,
    });
    addEdge('sample_execution', 'process_delta', 'correlated_with_game_context', 'correlated');
  }

  if (diff.persistenceLikeFiles.length) {
    addNode('persistence_artifact', 'persistence', 'Startup-path artifact appeared during game-context run', {
      files: diff.persistenceLikeFiles,
    });
    addEdge('sample_execution', 'persistence_artifact', 'appeared_after_execution', 'observed');
  }

  return {
    version: ANALYSIS_VERSION,
    nodes,
    edges,
    limits: [
      'Correlation does not by itself prove process injection or intent.',
      'A process-interaction claim requires direct telemetry evidence.',
    ],
  };
}

function comparativeVerdict({ neutralAssessment, gameAssessment, diff }) {
  const verdicts = [neutralAssessment && neutralAssessment.verdict, gameAssessment && gameAssessment.verdict, diff && diff.verdict];
  if (verdicts.includes('malicious')) return 'malicious';
  if (verdicts.includes('suspicious')) return 'suspicious';
  return 'inconclusive';
}

module.exports = {
  ANALYSIS_VERSION,
  behaviorDiff,
  buildCausalityMap,
  comparativeVerdict,
};
