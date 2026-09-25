'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

(() => {
  const root = path.join(__dirname, '..');
  const source = fs.readFileSync(path.join(root, 'desktop-app', 'sandbox', 'windows-sandbox', 'guest-harness.ps1'), 'utf8');

  assert.match(source, /'\.asi'/);
  assert.match(source, /'\.dll'/);
  assert.match(source, /MalGuardGtaPluginLoader/);
  assert.match(source, /LoadLibraryW/);
  assert.match(source, /FreeLibrary/);
  assert.match(source, /pluginLoaderScript/);
  assert.match(source, /Start-Process -FilePath 'powershell\.exe'/);
  assert.match(source, /networkPolicy = 'disabled-by-wsb'/);
  assert.match(source, /taskkill\.exe \/PID/);
  assert.match(source, /Remove-Item -LiteralPath \$pluginLoaderScript/);

  // The plugin loader must remain a child process. Loading the sample directly
  // into the telemetry harness would let a crashing plugin destroy evidence.
  assert.doesNotMatch(source, /\[MalGuardGtaPluginLoader\]::LoadLibraryW\(\$SamplePath\)/);

  console.log('✓ GTA plugin Windows Sandbox loader: isolated child loading, timeout and cleanup contract PASS');
})();
