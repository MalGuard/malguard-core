'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const { createHash } = require('crypto');
const { validateTelemetry, evaluateTelemetry, MAX_RESULT_BYTES } = require('./telemetry-validator.js');
const { behaviorDiff, buildCausalityMap, comparativeVerdict } = require('./game-context-analysis.js');

const GTA_CONTEXT_VERSION = '1.1.0';
const ALLOWED_SAMPLE_EXTENSIONS = new Set(['.exe', '.com', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.asi', '.dll']);

function xmlEscape(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

async function sha256File(filePath) {
  const bytes = await fs.promises.readFile(filePath);
  return createHash('sha256').update(bytes).digest('hex');
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

class RealGtaContextRunner {
  constructor({
    windowsBackend,
    gameRoot = process.env.MALGUARD_GTA_V_ROOT || '',
    gameExecutable = process.env.MALGUARD_GTA_V_EXE || 'GTA5.exe',
    observeSeconds = 12,
    gameStartupSeconds = 20,
    gamePrepareSeconds = 900,
    sessionRoot = null,
    preserveSessions = false,
  } = {}) {
    if (!windowsBackend || typeof windowsBackend.capabilities !== 'function' || typeof windowsBackend.executablePath !== 'function') {
      throw new TypeError('windowsBackend is required');
    }
    this.windowsBackend = windowsBackend;
    this.gameRoot = gameRoot ? path.resolve(gameRoot) : '';
    this.gameExecutable = String(gameExecutable || 'GTA5.exe');
    this.observeSeconds = Math.max(3, Math.min(60, Number(observeSeconds) || 12));
    this.gameStartupSeconds = Math.max(3, Math.min(90, Number(gameStartupSeconds) || 20));
    this.gamePrepareSeconds = Math.max(60, Math.min(1800, Number(gamePrepareSeconds) || 900));
    this.sessionRoot = path.resolve(sessionRoot || path.join(os.tmpdir(), 'malguard-gta-context'));
    this.preserveSessions = preserveSessions === true;
    this.harnessSource = path.join(__dirname, 'windows-sandbox', 'gta-context-harness.ps1');
  }

  async configurationStatus() {
    if (!this.gameRoot) {
      return { ok: false, code: 'GTA_CONTEXT_NOT_CONFIGURED', version: GTA_CONTEXT_VERSION };
    }
    const rootStat = await fs.promises.lstat(this.gameRoot).catch(() => null);
    if (!rootStat || !rootStat.isDirectory() || rootStat.isSymbolicLink()) {
      return { ok: false, code: 'GTA_CONTEXT_ROOT_INVALID', version: GTA_CONTEXT_VERSION };
    }
    const executableHostPath = path.resolve(this.gameRoot, this.gameExecutable);
    if (!(executableHostPath === this.gameRoot || executableHostPath.startsWith(this.gameRoot + path.sep))) {
      return { ok: false, code: 'GTA_CONTEXT_EXECUTABLE_ESCAPES_ROOT', version: GTA_CONTEXT_VERSION };
    }
    const exeStat = await fs.promises.lstat(executableHostPath).catch(() => null);
    if (!exeStat || !exeStat.isFile() || exeStat.isSymbolicLink()) {
      return { ok: false, code: 'GTA_CONTEXT_EXECUTABLE_NOT_FOUND', version: GTA_CONTEXT_VERSION };
    }
    return {
      ok: true,
      code: 'GTA_CONTEXT_CONFIGURED',
      version: GTA_CONTEXT_VERSION,
      gameRoot: this.gameRoot,
      executableHostPath,
      gameExecutable: path.relative(this.gameRoot, executableHostPath),
      stagingMode: 'sandbox-local-full-copy',
      hostGameReadOnly: true,
    };
  }

  buildWsbConfig({ inputHost, outputHost, sessionId, gameRoot, gameExecutableRelative }) {
    const ext = path.extname(inputHost.samplePath).toLowerCase();
    const command = [
      'powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned',
      '-File C:\\MalGuardInput\\gta-context-harness.ps1',
      '-SamplePath C:\\MalGuardInput\\sample' + ext,
      '-GameSourceRoot "C:\\MalGuardGameSource"',
      '-GameExecutableRelative ' + `"${String(gameExecutableRelative).replace(/"/g, '')}"`,
      '-OutputPath C:\\MalGuardOutput\\result.json',
      '-SessionId ' + sessionId,
      '-ObserveSeconds ' + this.observeSeconds,
      '-GameStartupSeconds ' + this.gameStartupSeconds,
      '-GamePrepareSeconds ' + this.gamePrepareSeconds,
    ].join(' ');

    return `<?xml version="1.0" encoding="utf-8"?>\n<Configuration>\n  <VGpu>Enable</VGpu>\n  <Networking>Disable</Networking>\n  <AudioInput>Disable</AudioInput>\n  <VideoInput>Disable</VideoInput>\n  <PrinterRedirection>Disable</PrinterRedirection>\n  <ClipboardRedirection>Disable</ClipboardRedirection>\n  <ProtectedClient>Enable</ProtectedClient>\n  <MemoryInMB>4096</MemoryInMB>\n  <MappedFolders>\n    <MappedFolder><HostFolder>${xmlEscape(inputHost.dir)}</HostFolder><SandboxFolder>C:\\MalGuardInput</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder>\n    <MappedFolder><HostFolder>${xmlEscape(gameRoot)}</HostFolder><SandboxFolder>C:\\MalGuardGameSource</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder>\n    <MappedFolder><HostFolder>${xmlEscape(outputHost)}</HostFolder><SandboxFolder>C:\\MalGuardOutput</SandboxFolder><ReadOnly>false</ReadOnly></MappedFolder>\n  </MappedFolders>\n  <LogonCommand><Command>${xmlEscape(command)}</Command></LogonCommand>\n</Configuration>\n`;
  }

  async _prepareSession(samplePath, expectedIdentity, config) {
    const resolvedSample = path.resolve(samplePath);
    const ext = path.extname(resolvedSample).toLowerCase();
    if (!ALLOWED_SAMPLE_EXTENSIONS.has(ext)) {
      const error = new Error('sample type is not supported by GTA behavioral context');
      error.code = 'GTA_CONTEXT_SAMPLE_TYPE_UNSUPPORTED';
      throw error;
    }
    const stat = await requireRegularFile(resolvedSample, 'GTA_CONTEXT_SAMPLE_INVALID');
    if (stat.size <= 0 || stat.size > 64 * 1024 * 1024) {
      const error = new Error('sample size invalid');
      error.code = 'GTA_CONTEXT_SAMPLE_SIZE_INVALID';
      throw error;
    }
    const sha256 = await sha256File(resolvedSample);
    if (expectedIdentity && expectedIdentity.sha256 && expectedIdentity.sha256 !== sha256) {
      const error = new Error('sample identity changed after preflight');
      error.code = 'GTA_CONTEXT_SAMPLE_IDENTITY_MISMATCH';
      throw error;
    }

    const sessionId = crypto.randomUUID();
    const root = path.join(this.sessionRoot, sessionId);
    const inputDir = path.join(root, 'input');
    const outputDir = path.join(root, 'output');
    await fs.promises.mkdir(inputDir, { recursive: true, mode: 0o700 });
    await fs.promises.mkdir(outputDir, { recursive: true, mode: 0o700 });
    const copiedSample = path.join(inputDir, `sample${ext}`);
    await fs.promises.copyFile(resolvedSample, copiedSample, fs.constants.COPYFILE_EXCL);
    await fs.promises.copyFile(this.harnessSource, path.join(inputDir, 'gta-context-harness.ps1'), fs.constants.COPYFILE_EXCL);
    const copiedSha = await sha256File(copiedSample);
    if (copiedSha !== sha256) {
      const error = new Error('sample staging hash mismatch');
      error.code = 'GTA_CONTEXT_STAGING_INTEGRITY_FAILED';
      throw error;
    }
    const wsbPath = path.join(root, 'gta-context.wsb');
    await fs.promises.writeFile(wsbPath, this.buildWsbConfig({
      inputHost: { dir: inputDir, samplePath: copiedSample },
      outputHost: outputDir,
      sessionId,
      gameRoot: config.gameRoot,
      gameExecutableRelative: config.gameExecutable,
    }), { flag: 'wx', mode: 0o600 });
    return { sessionId, root, inputDir, outputDir, wsbPath, sampleSha256: sha256, sampleExtension: ext };
  }

  async _readResult(resultPath, sessionId) {
    const stat = await fs.promises.lstat(resultPath);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size <= 0 || stat.size > MAX_RESULT_BYTES) {
      return { ok: false, code: 'GTA_CONTEXT_RESULT_INVALID' };
    }
    const raw = await fs.promises.readFile(resultPath, 'utf8');
    let parsed;
    try { parsed = JSON.parse(raw.replace(/^\uFEFF/, '')); }
    catch (_) { return { ok: false, code: 'GTA_CONTEXT_RESULT_JSON_INVALID' }; }
    const validated = validateTelemetry(parsed, sessionId);
    if (!validated.ok) return validated;
    if (!parsed.gameContext || parsed.gameContext.realGame !== true || parsed.gameContext.fixtureStarted !== true || parsed.gameContext.hostGameReadOnly !== true) {
      return { ok: false, code: 'REAL_GTA_CONTEXT_NOT_PROVEN' };
    }
    validated.telemetry.gameContext = parsed.gameContext;
    return validated;
  }

  async analyze(samplePath, expectedIdentity = null) {
    const config = await this.configurationStatus();
    if (!config.ok) return { ok: false, verdict: 'inconclusive', code: config.code, gameContext: config };

    const caps = await this.windowsBackend.capabilities();
    if (!caps.releaseGrade) {
      return {
        ok: false,
        verdict: 'inconclusive',
        code: caps.available ? 'HARDENED_WINDOWS_SANDBOX_ACCEPTANCE_PENDING' : 'WINDOWS_SANDBOX_UNAVAILABLE',
        backend: caps,
        gameContext: config,
      };
    }

    let session;
    try { session = await this._prepareSession(samplePath, expectedIdentity, config); }
    catch (error) {
      return { ok: false, verdict: 'inconclusive', code: error.code || 'GTA_CONTEXT_STAGING_FAILED', backend: caps, gameContext: config };
    }

    const resultPath = path.join(session.outputDir, 'result.json');
    return new Promise((resolve) => {
      let settled = false;
      let poller = null;
      let timer = null;
      const child = spawn(this.windowsBackend.executablePath(), [session.wsbPath], {
        stdio: 'ignore',
        windowsHide: true,
        shell: false,
      });
      const finish = async (result) => {
        if (settled) return;
        settled = true;
        if (poller) clearInterval(poller);
        if (timer) clearTimeout(timer);
        try { if (!child.killed) child.kill(); } catch (_) {}
        if (!this.preserveSessions) await fs.promises.rm(session.root, { recursive: true, force: true }).catch(() => {});
        resolve(result);
      };
      poller = setInterval(async () => {
        try {
          await fs.promises.access(resultPath, fs.constants.R_OK);
          const checked = await this._readResult(resultPath, session.sessionId);
          if (!checked.ok) {
            if (checked.code === 'GTA_CONTEXT_RESULT_JSON_INVALID') return;
            return finish({ ok: false, verdict: 'inconclusive', code: checked.code, backend: caps, sampleSha256: session.sampleSha256, gameContext: config });
          }
          const execution = checked.telemetry.execution || {};
          if (execution.attempted !== true || execution.started !== true) {
            return finish({
              ok: false,
              verdict: 'inconclusive',
              code: session.sampleExtension === '.asi' || session.sampleExtension === '.dll'
                ? 'GTA_PLUGIN_LOAD_NOT_PROVEN'
                : 'GTA_CONTEXT_SAMPLE_EXECUTION_NOT_PROVEN',
              backend: caps,
              sampleSha256: session.sampleSha256,
              telemetry: checked.telemetry,
              gameContext: { ...config, proven: true, realGame: true },
            });
          }
          const assessment = evaluateTelemetry(checked.telemetry);
          const diff = behaviorDiff({ execution: {}, baselineProcesses: [], finalProcesses: [], recentFiles: [] }, checked.telemetry);
          const causality = buildCausalityMap({ neutralTelemetry: null, gameTelemetry: checked.telemetry, diff });
          const verdict = comparativeVerdict({ neutralAssessment: null, gameAssessment: assessment, diff });
          return finish({
            ok: true,
            verdict,
            releaseGrade: true,
            sandboxLaunched: true,
            sampleExecutionStarted: true,
            backend: caps,
            sampleSha256: session.sampleSha256,
            telemetry: checked.telemetry,
            behaviorAssessment: assessment,
            gameContextDiff: diff,
            causality,
            gameContext: { ...config, proven: true, realGame: true },
            note: 'Real GTA context was observed inside Windows Sandbox using a sandbox-local writable clone. The host GTA installation remained read-only. Lack of suspicious behavior never proves SAFE by itself.',
          });
        } catch (_) {}
      }, 250);
      if (typeof poller.unref === 'function') poller.unref();
      timer = setTimeout(() => finish({
        ok: false,
        verdict: 'inconclusive',
        code: 'GTA_CONTEXT_TIMEOUT',
        backend: caps,
        sampleSha256: session.sampleSha256,
        gameContext: config,
      }), Math.max(120000, (this.gamePrepareSeconds + this.gameStartupSeconds + this.observeSeconds + 30) * 1000));
      child.once('error', error => finish({
        ok: false,
        verdict: 'inconclusive',
        code: 'GTA_CONTEXT_SANDBOX_LAUNCH_FAILED',
        detail: error.message,
        backend: caps,
        sampleSha256: session.sampleSha256,
        gameContext: config,
      }));
    });
  }
}

module.exports = { RealGtaContextRunner, GTA_CONTEXT_VERSION, ALLOWED_SAMPLE_EXTENSIONS };
