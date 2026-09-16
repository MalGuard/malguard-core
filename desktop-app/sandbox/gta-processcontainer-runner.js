'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { createHash } = require('crypto');
const { validateTelemetry, evaluateTelemetry, MAX_RESULT_BYTES } = require('./telemetry-validator.js');
const { behaviorDiff, buildCausalityMap, comparativeVerdict } = require('./game-context-analysis.js');

const PROCESSCONTAINER_GTA_VERSION = '0.2.0';
const NATIVE_HARNESS_NAME = 'MalGuardGtaContextHarness.exe';
const SUPPORTED_EXTENSIONS = new Set(['.exe', '.com', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.asi', '.dll']);
const CONTEXT_KINDS = new Set(['real-gta', 'synthetic-gta-compatible']);

function quoteWindows(value) {
  return `"${String(value).replace(/"/g, '\\"')}"`;
}

async function sha256File(filePath) {
  const handle = await fs.promises.open(filePath, fs.constants.O_RDONLY);
  try {
    const hash = createHash('sha256');
    const stream = handle.createReadStream();
    for await (const chunk of stream) hash.update(chunk);
    return hash.digest('hex');
  } finally {
    await handle.close().catch(() => {});
  }
}

async function requireRegularFile(filePath, code) {
  const stat = await fs.promises.lstat(filePath);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    const error = new Error(code);
    error.code = code;
    throw error;
  }
  return stat;
}

async function copyTreeNoLinks(sourceRoot, destinationRoot) {
  const sourceStat = await fs.promises.lstat(sourceRoot);
  if (!sourceStat.isDirectory() || sourceStat.isSymbolicLink()) {
    const error = new Error('GTA source root is not a regular directory');
    error.code = 'GTA_PROCESSCONTAINER_SOURCE_INVALID';
    throw error;
  }
  await fs.promises.mkdir(destinationRoot, { recursive: true, mode: 0o700 });
  const stack = [[sourceRoot, destinationRoot]];
  while (stack.length) {
    const [srcDir, dstDir] = stack.pop();
    const entries = await fs.promises.readdir(srcDir, { withFileTypes: true });
    for (const entry of entries) {
      const src = path.join(srcDir, entry.name);
      const dst = path.join(dstDir, entry.name);
      const stat = await fs.promises.lstat(src);
      if (stat.isSymbolicLink()) {
        const error = new Error(`Refusing GTA tree link: ${src}`);
        error.code = 'GTA_PROCESSCONTAINER_SOURCE_LINK_REJECTED';
        throw error;
      }
      if (stat.isDirectory()) {
        await fs.promises.mkdir(dst, { recursive: false, mode: 0o700 });
        stack.push([src, dst]);
      } else if (stat.isFile()) {
        try {
          await fs.promises.copyFile(src, dst, fs.constants.COPYFILE_FICLONE);
        } catch (_) {
          await fs.promises.copyFile(src, dst);
        }
      } else {
        const error = new Error(`Unsupported GTA tree entry: ${src}`);
        error.code = 'GTA_PROCESSCONTAINER_SOURCE_ENTRY_REJECTED';
        throw error;
      }
    }
  }
}

class GtaProcessContainerRunner {
  constructor({
    gameRoot = process.env.MALGUARD_GTA_V_ROOT || '',
    gameExecutable = process.env.MALGUARD_GTA_V_EXE || 'GTA5.exe',
    observeSeconds = 12,
    gameStartupSeconds = 20,
    sessionRoot = null,
    preserveSessions = false,
    sdkLoader = null,
    harnessExecutable = process.env.MALGUARD_GTA_PROCESSCONTAINER_HARNESS_EXE || '',
    contextKind = 'real-gta',
  } = {}) {
    if (!CONTEXT_KINDS.has(contextKind)) throw new Error('invalid GTA ProcessContainer context kind');
    this.gameRoot = gameRoot ? path.resolve(gameRoot) : '';
    this.gameExecutable = String(gameExecutable || 'GTA5.exe');
    this.observeSeconds = Math.max(3, Math.min(60, Number(observeSeconds) || 12));
    this.gameStartupSeconds = Math.max(3, Math.min(90, Number(gameStartupSeconds) || 20));
    this.sessionRoot = path.resolve(sessionRoot || path.join(os.tmpdir(), 'malguard-gta-processcontainer'));
    this.preserveSessions = preserveSessions === true;
    this.sdkLoader = sdkLoader || (() => import('@microsoft/mxc-sdk'));
    this.contextKind = contextKind;
    this.harnessSource = path.resolve(harnessExecutable || path.join(__dirname, 'bin', NATIVE_HARNESS_NAME));
  }

  async configurationStatus() {
    if (!this.gameRoot) return { ok: false, code: 'GTA_CONTEXT_NOT_CONFIGURED', version: PROCESSCONTAINER_GTA_VERSION };
    const rootStat = await fs.promises.lstat(this.gameRoot).catch(() => null);
    if (!rootStat || !rootStat.isDirectory() || rootStat.isSymbolicLink()) {
      return { ok: false, code: 'GTA_CONTEXT_ROOT_INVALID', version: PROCESSCONTAINER_GTA_VERSION };
    }
    const executableHostPath = path.resolve(this.gameRoot, this.gameExecutable);
    if (!(executableHostPath === this.gameRoot || executableHostPath.startsWith(this.gameRoot + path.sep))) {
      return { ok: false, code: 'GTA_CONTEXT_EXECUTABLE_ESCAPES_ROOT', version: PROCESSCONTAINER_GTA_VERSION };
    }
    const exeStat = await fs.promises.lstat(executableHostPath).catch(() => null);
    if (!exeStat || !exeStat.isFile() || exeStat.isSymbolicLink()) {
      return { ok: false, code: 'GTA_CONTEXT_EXECUTABLE_NOT_FOUND', version: PROCESSCONTAINER_GTA_VERSION };
    }
    return {
      ok: true,
      code: 'GTA_PROCESSCONTAINER_CONTEXT_CONFIGURED',
      version: PROCESSCONTAINER_GTA_VERSION,
      gameRoot: this.gameRoot,
      executableHostPath,
      gameExecutable: path.relative(this.gameRoot, executableHostPath),
      contextKind: this.contextKind,
      containment: 'processcontainer',
      requiresNestedVirtualization: false,
      hostGameReadOnly: true,
      stagingMode: 'host-created-ephemeral-game-clone',
    };
  }

  async supportStatus() {
    if (process.platform !== 'win32') {
      return { ok: false, code: 'GTA_PROCESSCONTAINER_WINDOWS_REQUIRED', requiresNestedVirtualization: false };
    }
    let sdk;
    try { sdk = await this.sdkLoader(); }
    catch (error) {
      return { ok: false, code: 'GTA_PROCESSCONTAINER_SDK_UNAVAILABLE', detail: error.message, requiresNestedVirtualization: false };
    }
    let support;
    try { support = sdk.getPlatformSupport(); }
    catch (error) {
      return { ok: false, code: 'GTA_PROCESSCONTAINER_SUPPORT_CHECK_FAILED', detail: error.message, requiresNestedVirtualization: false };
    }
    const available = !!(support && support.isSupported === true && Array.isArray(support.availableMethods) && support.availableMethods.includes('processcontainer'));
    return {
      ok: available,
      code: available ? 'GTA_PROCESSCONTAINER_AVAILABLE' : 'GTA_PROCESSCONTAINER_UNAVAILABLE',
      requiresNestedVirtualization: false,
      isolationTier: support && support.isolationTier ? support.isolationTier : null,
      isolationWarnings: support && Array.isArray(support.isolationWarnings) ? support.isolationWarnings : [],
      sdk,
    };
  }

  async _prepareSession(samplePath, expectedIdentity, config) {
    const resolvedSample = path.resolve(samplePath);
    const ext = path.extname(resolvedSample).toLowerCase();
    if (!SUPPORTED_EXTENSIONS.has(ext)) {
      const error = new Error('sample type is not supported by GTA ProcessContainer');
      error.code = 'GTA_PROCESSCONTAINER_SAMPLE_TYPE_UNSUPPORTED';
      throw error;
    }
    const stat = await requireRegularFile(resolvedSample, 'GTA_PROCESSCONTAINER_SAMPLE_INVALID');
    if (stat.size <= 0 || stat.size > 64 * 1024 * 1024) {
      const error = new Error('sample size invalid');
      error.code = 'GTA_PROCESSCONTAINER_SAMPLE_SIZE_INVALID';
      throw error;
    }
    const harnessStat = await fs.promises.lstat(this.harnessSource).catch(() => null);
    if (!harnessStat || !harnessStat.isFile() || harnessStat.isSymbolicLink()) {
      const error = new Error('native GTA ProcessContainer harness is unavailable');
      error.code = 'GTA_PROCESSCONTAINER_NATIVE_HARNESS_MISSING';
      throw error;
    }
    const sha256 = await sha256File(resolvedSample);
    if (expectedIdentity && expectedIdentity.sha256 && expectedIdentity.sha256 !== sha256) {
      const error = new Error('sample identity changed after preflight');
      error.code = 'GTA_PROCESSCONTAINER_SAMPLE_IDENTITY_MISMATCH';
      throw error;
    }

    const sessionId = crypto.randomUUID();
    const root = path.join(this.sessionRoot, sessionId);
    const inputDir = path.join(root, 'input');
    const runtimeRoot = path.join(root, 'runtime');
    const runtimeGame = path.join(runtimeRoot, 'game');
    const outputDir = path.join(root, 'output');
    await fs.promises.mkdir(inputDir, { recursive: true, mode: 0o700 });
    await fs.promises.mkdir(outputDir, { recursive: true, mode: 0o700 });
    await copyTreeNoLinks(config.gameRoot, runtimeGame);

    const runtimeGameExe = path.resolve(runtimeGame, config.gameExecutable);
    if (!(runtimeGameExe === runtimeGame || runtimeGameExe.startsWith(runtimeGame + path.sep))) {
      const error = new Error('runtime GTA executable escaped clone root');
      error.code = 'GTA_PROCESSCONTAINER_RUNTIME_EXE_ESCAPES_ROOT';
      throw error;
    }
    await requireRegularFile(runtimeGameExe, 'GTA_PROCESSCONTAINER_RUNTIME_EXE_MISSING');

    const sampleName = `MalGuardSample${ext}`;
    const stagedSample = path.join(runtimeGame, sampleName);
    await fs.promises.copyFile(resolvedSample, stagedSample, fs.constants.COPYFILE_EXCL);
    if (await sha256File(stagedSample) !== sha256) {
      const error = new Error('sample staging hash mismatch');
      error.code = 'GTA_PROCESSCONTAINER_STAGING_INTEGRITY_FAILED';
      throw error;
    }

    const stagedHarness = path.join(inputDir, NATIVE_HARNESS_NAME);
    await fs.promises.copyFile(this.harnessSource, stagedHarness, fs.constants.COPYFILE_EXCL);
    if (await sha256File(stagedHarness) !== await sha256File(this.harnessSource)) {
      const error = new Error('native harness staging hash mismatch');
      error.code = 'GTA_PROCESSCONTAINER_HARNESS_INTEGRITY_FAILED';
      throw error;
    }

    return {
      sessionId,
      root,
      inputDir,
      runtimeRoot,
      runtimeGame,
      outputDir,
      runtimeGameExe,
      stagedSample,
      stagedHarness,
      sampleName,
      sampleExtension: ext,
      sampleSha256: sha256,
      resultPath: path.join(outputDir, 'result.json'),
    };
  }

  buildPolicy(session) {
    return {
      version: '0.8.0-alpha',
      filesystem: {
        readonlyPaths: [session.inputDir],
        readwritePaths: [session.runtimeRoot, session.outputDir],
      },
      network: {
        allowOutbound: false,
        allowLocalNetwork: false,
      },
      ui: { allowWindows: true },
      timeoutMs: Math.max(60_000, (this.gameStartupSeconds + this.observeSeconds + 30) * 1000),
    };
  }

  buildCommand(session) {
    return [
      quoteWindows(session.stagedHarness),
      quoteWindows(session.stagedSample),
      quoteWindows(session.runtimeGameExe),
      quoteWindows(session.resultPath),
      quoteWindows(session.sessionId),
      String(this.observeSeconds),
      String(this.gameStartupSeconds),
      this.contextKind,
    ].join(' ');
  }

  async _readResult(session) {
    const stat = await fs.promises.lstat(session.resultPath).catch(() => null);
    if (!stat || !stat.isFile() || stat.isSymbolicLink() || stat.size <= 0 || stat.size > MAX_RESULT_BYTES) {
      return { ok: false, code: 'GTA_PROCESSCONTAINER_RESULT_INVALID' };
    }
    let parsed;
    try { parsed = JSON.parse((await fs.promises.readFile(session.resultPath, 'utf8')).replace(/^\uFEFF/, '')); }
    catch (_) { return { ok: false, code: 'GTA_PROCESSCONTAINER_RESULT_JSON_INVALID' }; }
    const gameContext = parsed.gameContext;
    if (!gameContext || gameContext.fixtureStarted !== true || gameContext.containment !== 'processcontainer' || gameContext.contextKind !== this.contextKind) {
      return { ok: false, code: 'GTA_PROCESSCONTAINER_CONTEXT_NOT_PROVEN' };
    }
    if (this.contextKind === 'real-gta' && gameContext.realGame !== true) {
      return { ok: false, code: 'GTA_PROCESSCONTAINER_REAL_GAME_NOT_PROVEN' };
    }
    if (this.contextKind === 'synthetic-gta-compatible' && (gameContext.realGame !== false || gameContext.syntheticFixture !== true)) {
      return { ok: false, code: 'GTA_PROCESSCONTAINER_SYNTHETIC_CONTEXT_INVALID' };
    }
    const validated = validateTelemetry(parsed, session.sessionId);
    if (!validated.ok) return validated;
    validated.telemetry.gameContext = gameContext;
    return validated;
  }

  async analyze(samplePath, expectedIdentity = null) {
    const config = await this.configurationStatus();
    if (!config.ok) return { ok: false, verdict: 'inconclusive', code: config.code, gameContext: config };
    const support = await this.supportStatus();
    if (!support.ok) return { ok: false, verdict: 'inconclusive', code: support.code, backend: support, gameContext: config };

    let session;
    try { session = await this._prepareSession(samplePath, expectedIdentity, config); }
    catch (error) {
      return { ok: false, verdict: 'inconclusive', code: error.code || 'GTA_PROCESSCONTAINER_STAGING_FAILED', detail: error.message, backend: { ...support, sdk: undefined }, gameContext: config };
    }

    try {
      const policy = this.buildPolicy(session);
      const sdk = support.sdk;
      const containerConfig = sdk.createConfigFromPolicy(policy, 'process');
      containerConfig.process.commandLine = this.buildCommand(session);
      containerConfig.process.cwd = session.runtimeGame;
      const child = sdk.spawnSandboxFromConfig(containerConfig, { usePty: false });
      const exit = await new Promise((resolve) => {
        let stdout = '';
        let stderr = '';
        child.stdout?.on('data', chunk => { if (stdout.length < 32768) stdout += chunk.toString('utf8'); });
        child.stderr?.on('data', chunk => { if (stderr.length < 32768) stderr += chunk.toString('utf8'); });
        child.once('error', error => resolve({ code: null, signal: null, error: error.message, stdout, stderr }));
        child.once('close', (code, signal) => resolve({ code, signal, error: null, stdout, stderr }));
      });
      const checked = await this._readResult(session);
      if (!checked.ok) {
        return { ok: false, verdict: 'inconclusive', code: checked.code, backend: { ...support, sdk: undefined }, process: exit, sampleSha256: session.sampleSha256, gameContext: config };
      }
      const execution = checked.telemetry.execution || {};
      if (execution.attempted !== true || execution.started !== true) {
        return {
          ok: false,
          verdict: 'inconclusive',
          code: session.sampleExtension === '.asi' || session.sampleExtension === '.dll' ? 'GTA_PLUGIN_LOAD_NOT_PROVEN' : 'GTA_CONTEXT_SAMPLE_EXECUTION_NOT_PROVEN',
          backend: { ...support, sdk: undefined },
          process: exit,
          sampleSha256: session.sampleSha256,
          telemetry: checked.telemetry,
          gameContext: { ...config, proven: true, realGame: this.contextKind === 'real-gta' },
        };
      }
      const assessment = evaluateTelemetry(checked.telemetry);
      const diff = behaviorDiff({ execution: {}, baselineProcesses: [], finalProcesses: [], recentFiles: [] }, checked.telemetry);
      const causality = buildCausalityMap({ neutralTelemetry: null, gameTelemetry: checked.telemetry, diff });
      const verdict = comparativeVerdict({ neutralAssessment: null, gameAssessment: assessment, diff });
      const realGame = this.contextKind === 'real-gta';
      return {
        ok: true,
        verdict,
        releaseGrade: false,
        isolation: 'processcontainer',
        requiresNestedVirtualization: false,
        sampleExecutionStarted: true,
        backend: { ...support, sdk: undefined },
        process: exit,
        sampleSha256: session.sampleSha256,
        telemetry: checked.telemetry,
        behaviorAssessment: assessment,
        gameContextDiff: diff,
        causality,
        gameContext: { ...config, proven: true, realGame, syntheticFixture: !realGame },
        note: realGame
          ? 'GTA ran from an ephemeral writable clone inside Microsoft MXC ProcessContainer using the native MalGuard telemetry harness. ProcessContainer is a weaker isolation boundary than a hypervisor VM.'
          : 'A harmless GTA-compatible fixture ran end-to-end inside Microsoft MXC ProcessContainer using the native MalGuard telemetry harness. This validates the containment, staging, plugin-load observation, and telemetry path but is not evidence that the actual GTA V binary was executed.',
      };
    } finally {
      if (!this.preserveSessions && session) await fs.promises.rm(session.root, { recursive: true, force: true }).catch(() => {});
    }
  }
}

module.exports = { GtaProcessContainerRunner, PROCESSCONTAINER_GTA_VERSION, NATIVE_HARNESS_NAME, SUPPORTED_EXTENSIONS, copyTreeNoLinks };
