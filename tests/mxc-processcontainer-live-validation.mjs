import fsp from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import {
  createConfigFromPolicy,
  spawnSandboxFromConfig,
  getPlatformSupport,
} from '@microsoft/mxc-sdk';

function quote(value) {
  return `"${String(value).replaceAll('"', '\\"')}"`;
}

function connectOnce(port, timeoutMs = 1500) {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host: '127.0.0.1', port });
    let settled = false;
    const finish = (ok) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(ok);
    };
    socket.setTimeout(timeoutMs, () => finish(false));
    socket.once('connect', () => finish(true));
    socket.once('error', () => finish(false));
  });
}

function listenLoopback() {
  return new Promise((resolve, reject) => {
    const server = net.createServer((socket) => {
      socket.on('error', () => {});
      socket.end();
    });
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve(server));
  });
}

function waitForChild(child) {
  return new Promise((resolve, reject) => {
    let stdout = '';
    let stderr = '';
    child.stdout?.on('data', (chunk) => { stdout += chunk.toString('utf8'); });
    child.stderr?.on('data', (chunk) => { stderr += chunk.toString('utf8'); });
    child.once('error', reject);
    child.once('close', (code, signal) => resolve({ code, signal, stdout, stderr }));
  });
}

const childExe = process.env.MALGUARD_MXC_CHILD_EXE;
if (!childExe) throw new Error('MALGUARD_MXC_CHILD_EXE is required');

const support = getPlatformSupport();
console.log('MXC platform support:', JSON.stringify(support));
if (!support || support.isSupported !== true || !Array.isArray(support.availableMethods) || !support.availableMethods.includes('processcontainer')) {
  throw new Error(`MXC ProcessContainer is unavailable: ${JSON.stringify(support)}`);
}

const tempRoot = await fsp.mkdtemp(path.join(os.tmpdir(), 'malguard-mxc-processcontainer-'));
const inputRoot = path.join(tempRoot, 'input');
const outputRoot = path.join(tempRoot, 'output');
const deniedRoot = path.join(tempRoot, 'denied');
await fsp.mkdir(inputRoot, { recursive: true });
await fsp.mkdir(outputRoot, { recursive: true });
await fsp.mkdir(deniedRoot, { recursive: true });

const deniedMarker = path.join(deniedRoot, 'host-marker.txt');
const resultPath = path.join(outputRoot, 'result.json');
const copiedChild = path.join(inputRoot, path.basename(childExe));
await fsp.writeFile(deniedMarker, 'MALGUARD_HOST_ONLY_MARKER\n', 'utf8');
await fsp.copyFile(childExe, copiedChild);

const server = await listenLoopback();
const port = server.address().port;
const hostBaselineConnected = await connectOnce(port);
if (!hostBaselineConnected) {
  server.close();
  await fsp.rm(tempRoot, { recursive: true, force: true });
  throw new Error('Host loopback baseline failed; network-denial result would be ambiguous');
}

const previousSecret = process.env.MALGUARD_MXC_HOST_SECRET;
process.env.MALGUARD_MXC_HOST_SECRET = 'synthetic-secret-must-not-cross-boundary';

try {
  const config = createConfigFromPolicy({
    version: '0.8.0-alpha',
    filesystem: {
      readonlyPaths: [inputRoot],
      readwritePaths: [outputRoot],
    },
    network: {
      allowOutbound: false,
      allowLocalNetwork: false,
    },
    timeoutMs: 15_000,
  }, 'process');

  config.process.commandLine = [
    quote(copiedChild),
    quote(deniedMarker),
    quote(inputRoot),
    quote(resultPath),
    String(port),
  ].join(' ');
  config.process.cwd = inputRoot;

  const child = spawnSandboxFromConfig(config, { usePty: false });
  const result = await waitForChild(child);
  console.log('MXC child result:', JSON.stringify(result));

  let report;
  try {
    report = JSON.parse(await fsp.readFile(resultPath, 'utf8'));
  } catch (error) {
    throw new Error(`Synthetic native child did not produce a readable result: ${error.message}; stderr=${result.stderr}`);
  }

  const acceptance = {
    schemaVersion: '1.0.0',
    kind: 'malguard-mxc-processcontainer-live-validation',
    isolationTier: support.isolationTier || null,
    isolationWarnings: Array.isArray(support.isolationWarnings) ? support.isolationWarnings : [],
    hostBaselineConnected,
    childExitCode: result.code,
    childSignal: result.signal,
    syntheticOnly: report.syntheticOnly === true,
    deniedReadBlocked: report.deniedReadBlocked === true,
    readonlyWriteBlocked: report.readonlyWriteBlocked === true,
    networkDenied: report.networkDenied === true,
    hostSecretAbsent: report.hostSecretAbsent === true,
  };
  acceptance.ok = acceptance.childExitCode === 0 && acceptance.syntheticOnly &&
    acceptance.deniedReadBlocked && acceptance.readonlyWriteBlocked &&
    acceptance.networkDenied && acceptance.hostSecretAbsent;

  console.log(JSON.stringify(acceptance, null, 2));
  if (!acceptance.ok) process.exitCode = 20;
} finally {
  if (previousSecret === undefined) delete process.env.MALGUARD_MXC_HOST_SECRET;
  else process.env.MALGUARD_MXC_HOST_SECRET = previousSecret;
  await new Promise((resolve) => server.close(resolve));
  await fsp.rm(tempRoot, { recursive: true, force: true });
}
