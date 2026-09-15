import fsp from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import {
  createConfigFromPolicy,
  spawnSandboxFromConfig,
  getAvailableToolsPolicy,
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
    const server = net.createServer((socket) => socket.end('malguard-baseline'));
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

const support = getPlatformSupport();
console.log('MXC platform support:', JSON.stringify(support));
if (!support || support.isSupported !== true) {
  throw new Error(`MXC process containment is unavailable: ${JSON.stringify(support)}`);
}

const tempRoot = await fsp.mkdtemp(path.join(os.tmpdir(), 'malguard-mxc-processcontainer-'));
const inputRoot = path.join(tempRoot, 'input');
const deniedRoot = path.join(tempRoot, 'denied');
await fsp.mkdir(inputRoot, { recursive: true });
await fsp.mkdir(deniedRoot, { recursive: true });

const deniedMarker = path.join(deniedRoot, 'host-marker.txt');
await fsp.writeFile(deniedMarker, 'MALGUARD_HOST_ONLY_MARKER\n', 'utf8');
const childScript = path.join(inputRoot, 'synthetic-child.cjs');
await fsp.writeFile(childScript, String.raw`'use strict';
const fs = require('fs');
const net = require('net');
const path = require('path');

const deniedMarker = process.argv[2];
const inputRoot = process.argv[3];
const port = Number(process.argv[4]);

function tryNetwork() {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host: '127.0.0.1', port });
    let settled = false;
    const finish = (connected) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(connected);
    };
    socket.setTimeout(1200, () => finish(false));
    socket.once('connect', () => finish(true));
    socket.once('error', () => finish(false));
  });
}

(async () => {
  let deniedReadBlocked = false;
  let readonlyWriteBlocked = false;
  try { fs.readFileSync(deniedMarker); } catch (_) { deniedReadBlocked = true; }
  try { fs.writeFileSync(path.join(inputRoot, 'should-not-write.tmp'), 'blocked'); } catch (_) { readonlyWriteBlocked = true; }
  const networkConnected = await tryNetwork();
  const secretAbsent = process.env.MALGUARD_MXC_HOST_SECRET === undefined;
  const report = {
    syntheticOnly: true,
    deniedReadBlocked,
    readonlyWriteBlocked,
    networkDenied: !networkConnected,
    secretAbsent,
  };
  console.log(JSON.stringify(report));
  process.exit(deniedReadBlocked && readonlyWriteBlocked && !networkConnected && secretAbsent ? 0 : 31);
})().catch((error) => {
  console.error(error && error.stack ? error.stack : String(error));
  process.exit(32);
});
`, 'utf8');

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
  const tools = getAvailableToolsPolicy(process.env);
  const config = createConfigFromPolicy({
    version: '0.8.0-alpha',
    filesystem: {
      readonlyPaths: [...tools.readonlyPaths, inputRoot],
      readwritePaths: [],
    },
    network: {
      allowOutbound: false,
      allowLocalNetwork: false,
    },
    timeoutMs: 15_000,
  }, 'process');

  config.process.commandLine = [
    quote(process.execPath),
    quote(childScript),
    quote(deniedMarker),
    quote(inputRoot),
    String(port),
  ].join(' ');
  config.process.cwd = inputRoot;

  const child = spawnSandboxFromConfig(config, { usePty: false });
  const result = await waitForChild(child);
  console.log('MXC child result:', JSON.stringify(result));

  const lines = result.stdout.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const reportLine = lines.reverse().find((line) => line.startsWith('{') && line.endsWith('}'));
  if (!reportLine) throw new Error(`Synthetic child did not emit JSON. stderr=${result.stderr}`);
  const report = JSON.parse(reportLine);

  const acceptance = {
    schemaVersion: '1.0.0',
    kind: 'malguard-mxc-processcontainer-live-validation',
    hostBaselineConnected,
    childExitCode: result.code,
    childSignal: result.signal,
    syntheticOnly: report.syntheticOnly === true,
    deniedReadBlocked: report.deniedReadBlocked === true,
    readonlyWriteBlocked: report.readonlyWriteBlocked === true,
    networkDenied: report.networkDenied === true,
    hostSecretAbsent: report.secretAbsent === true,
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
