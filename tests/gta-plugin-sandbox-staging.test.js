'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { SUPPORTED_EXTENSIONS } = require('../desktop-app/sandbox/sandbox-controller.js');

const root = path.resolve(__dirname, '..');
const runner = fs.readFileSync(path.join(root, 'desktop-app', 'sandbox', 'gta-real-context-runner.js'), 'utf8');
const harness = fs.readFileSync(path.join(root, 'desktop-app', 'sandbox', 'windows-sandbox', 'gta-context-harness.ps1'), 'utf8');

assert(SUPPORTED_EXTENSIONS instanceof Set, 'sandbox controller must export supported extension policy');
assert(SUPPORTED_EXTENSIONS.has('.asi'), 'sandbox preflight must accept .asi samples');
assert(SUPPORTED_EXTENSIONS.has('.dll'), 'sandbox preflight must accept .dll samples');
assert(runner.includes("'.asi'"), 'GTA context runner must accept .asi samples');
assert(runner.includes("'.dll'"), 'GTA context runner must accept .dll samples');
assert(runner.includes('<SandboxFolder>C:\\\\MalGuardGameSource</SandboxFolder><ReadOnly>true</ReadOnly>'), 'host GTA mapping must remain read-only');
assert(runner.includes("stagingMode: 'sandbox-local-full-copy'"), 'runner must declare sandbox-local clone staging');
assert(harness.includes("$runtimeRoot = 'C:\\MalGuardRuntime\\Game'"), 'harness must use sandbox-local writable GTA runtime');
assert(harness.includes("Copy-Item -LiteralPath $SamplePath -Destination $stagedPlugin -Force"), 'plugin must be staged only into sandbox-local GTA runtime');
assert(harness.includes('$result.gameContext.pluginLoadProven = $true'), 'plugin execution must require observed module load');
assert(harness.includes('Test-ModuleLoaded'), 'plugin module load proof must be collected from GTA process modules');
assert(!harness.includes('Copy-Item -LiteralPath $SamplePath -Destination $GameSourceRoot'), 'sample must never be copied into host-mapped GTA source');

console.log('✓ GTA plugin sandbox staging keeps host game read-only and requires real module-load proof');
