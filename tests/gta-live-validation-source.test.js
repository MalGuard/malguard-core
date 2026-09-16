'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const workflow = fs.readFileSync(path.join(root, '.github', 'workflows', 'gta-sandbox-live-validation.yml'), 'utf8');
const driver = fs.readFileSync(path.join(root, 'tools', 'gta-live-validation.js'), 'utf8');
const fixture = fs.readFileSync(path.join(root, 'tests', 'fixtures', 'gta-benign-plugin.c'), 'utf8');
const runner = fs.readFileSync(path.join(root, 'desktop-app', 'sandbox', 'gta-real-context-runner.js'), 'utf8');
const harness = fs.readFileSync(path.join(root, 'desktop-app', 'sandbox', 'windows-sandbox', 'gta-context-harness.ps1'), 'utf8');

assert.match(workflow, /runs-on:\s*\[self-hosted, windows, malguard-sandbox, gta-v\]/);
assert.match(workflow, /MALGUARD_GTA_V_ROOT/);
assert.match(workflow, /WindowsSandbox\.exe/);
assert.match(workflow, /dinput8\.dll/);
assert.match(workflow, /gta-benign-plugin\.c/);
assert.match(workflow, /gta-live-validation\.js/);
assert.doesNotMatch(workflow, /Invoke-WebRequest|curl\s|wget\s|Start-BitsTransfer/i, 'live validation must not download GTA, loaders, or test binaries');

assert.match(fixture, /DllMain/);
assert.doesNotMatch(fixture, /CreateFile|RegSet|WinHttp|WinInet|CreateProcess|ShellExecute|socket\s*\(/i, 'benign fixture must remain inert');

assert.match(driver, /pluginLoadProven/);
assert.match(driver, /hostGameReadOnly/);
assert.match(driver, /sandbox-local-full-copy/);
assert.match(driver, /sandboxLaunched/);
assert.match(driver, /sampleExecutionStarted/);

assert.match(runner, /\.asi/);
assert.match(runner, /\.dll/);
assert.match(runner, /hostGameReadOnly:\s*true/);
assert.match(harness, /MalGuardRuntime\\Game/);
assert.match(harness, /pluginLoadProven/);
assert.match(harness, /Test-ModuleLoaded/);

console.log('✓ GTA live validation is wired to real-host evidence and an inert local acceptance fixture');
