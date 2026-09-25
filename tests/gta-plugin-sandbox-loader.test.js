'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

(() => {
  const root = path.join(__dirname, '..');
  const harness = fs.readFileSync(path.join(root, 'desktop-app', 'sandbox', 'windows-sandbox', 'guest-harness.ps1'), 'utf8');
  const backend = fs.readFileSync(path.join(root, 'desktop-app', 'sandbox', 'windows-sandbox-backend.js'), 'utf8');
  const controller = fs.readFileSync(path.join(root, 'desktop-app', 'sandbox', 'sandbox-controller.js'), 'utf8');

  assert.match(harness, /'\.asi'/);
  assert.match(harness, /'\.dll'/);
  assert.match(harness, /C:\\MalGuardGtaSim/);
  assert.match(harness, /GTA5\.exe\.simulated/);
  assert.match(harness, /MALGUARD_GTA_SIM/);
  assert.match(harness, /Copy-Item -LiteralPath \$SamplePath -Destination \$executionPath/);
  assert.match(harness, /MalGuardGtaPluginLoader/);
  assert.match(harness, /LoadLibraryW/);
  assert.match(harness, /FreeLibrary/);
  assert.match(harness, /networkPolicy = 'disabled-by-wsb'/);
  assert.match(harness, /taskkill\.exe \/PID/);
  assert.match(harness, /Remove-Item -LiteralPath \$pluginLoaderScript/);

  assert.doesNotMatch(harness, /Program Files.*Rockstar/i);
  assert.doesNotMatch(harness, /SteamLibrary/i);
  assert.doesNotMatch(harness, /Epic Games/i);

  assert.match(backend, /'\.asi','\.dll'/);
  assert.match(controller, /GTA_PLUGIN_WINDOWS_SANDBOX_REQUIRED/);
  assert.match(controller, /windowsSandboxBackend/);
  assert.match(controller, /hostFallback: false/);

  console.log('✓ GTA plugin loader contract: synthetic game tree, child DLL loader, deny-network telemetry and certified Windows-Sandbox-only routing PASS');
})();
