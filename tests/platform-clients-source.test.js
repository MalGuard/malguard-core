'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const client = path.join(root, 'clients', 'platform');

for (const required of [
  'package.json',
  'capacitor.config.json',
  'scripts/build-web.js',
  'web-src/index.html',
  'web-src/platform.js',
  'web-src/styles.css',
  'electron/main.js',
]) {
  assert.ok(fs.existsSync(path.join(client, ...required.split('/'))), `missing platform client file: ${required}`);
}

const electron = fs.readFileSync(path.join(client, 'electron', 'main.js'), 'utf8');
assert(/contextIsolation:\s*true/.test(electron), 'Electron context isolation must remain enabled');
assert(/nodeIntegration:\s*false/.test(electron), 'Electron renderer Node integration must remain disabled');
assert(/nodeIntegrationInWorker:\s*false/.test(electron), 'Electron worker Node integration must remain disabled');
assert(/sandbox:\s*true/.test(electron), 'Electron Chromium sandbox must remain enabled');
assert(/webSecurity:\s*true/.test(electron), 'Electron web security must remain enabled');
assert(/setPermissionRequestHandler[\s\S]*callback\(false\)/.test(electron), 'Electron permission requests must fail closed');

const html = fs.readFileSync(path.join(client, 'web-src', 'index.html'), 'utf8');
assert(/Content-Security-Policy/.test(html), 'platform UI must ship with a CSP');
assert(/worker-src 'self' blob:/.test(html), 'platform UI must explicitly constrain workers');
assert(/Windows behavioral Sandbox[\s\S]*Windows-only capability/.test(html), 'platform UI must not misrepresent Windows Sandbox availability');

const controller = fs.readFileSync(path.join(client, 'web-src', 'platform.js'), 'utf8');
assert(/MalGuardWorkerScanner\.scan\(file, 'pro'\)/.test(controller), 'platform client must use the existing bounded worker scanner');
assert(!/eval\s*\(|new Function\s*\(/.test(controller), 'platform client controller must not dynamically execute code');

const builder = fs.readFileSync(path.join(client, 'scripts', 'build-web.js'), 'utf8');
for (const core of ['scan-worker.js', 'scan-worker-client.js', 'engine.js', 'rules.json']) {
  assert(builder.includes(`'${core}'`), `shared platform bundle must include ${core}`);
}
assert(!builder.includes('desktop-app/threat-intel/credential-store.js'), 'mobile/mac static bundle must not include credential stores');

console.log('✓ Platform clients: iOS/Android/macOS shared scanner source and fail-closed shell security PASS');
