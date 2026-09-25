param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$lockPath = Join-Path $root 'desktop-app\multi-engine\engine-lock.json'
$target = Join-Path $root 'desktop-app\multi-engine\bin'
$lock = Get-Content -LiteralPath $lockPath -Raw | ConvertFrom-Json
if ($lock.schemaVersion -ne '1.0.0') { throw 'Unsupported multi-engine lock schema.' }

Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $target -Force | Out-Null
$temp = Join-Path $env:RUNNER_TEMP ('malguard-multi-engine-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp -Force | Out-Null

try {
  foreach ($name in @('yaraX','capa','floss')) {
    $entry = $lock.engines.$name
    if (-not $entry) { throw "Missing lock entry: $name" }

    $uri = [Uri]$entry.url
    if ($uri.Scheme -ne 'https' -or $uri.Host -ne 'github.com' -or $uri.AbsolutePath -notlike '*/releases/download/*') {
      throw "Untrusted engine origin: $($entry.url)"
    }
    if ([string]$entry.sha256 -notmatch '^[a-fA-F0-9]{64}$') { throw "Invalid SHA-256 lock for $name" }

    $archive = Join-Path $temp ([string]$entry.archive)
    Invoke-WebRequest -Uri $entry.url -OutFile $archive -MaximumRedirection 8

    $actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne ([string]$entry.sha256).ToLowerInvariant()) {
      throw "SHA-256 mismatch for $name: $actual"
    }

    $extract = Join-Path $temp $name
    New-Item -ItemType Directory -Path $extract -Force | Out-Null
    Expand-Archive -LiteralPath $archive -DestinationPath $extract -Force

    $exe = Get-ChildItem -LiteralPath $extract -Filter ([string]$entry.executable) -File -Recurse | Select-Object -First 1
    if (-not $exe) { throw "Executable not found for $name: $($entry.executable)" }

    $dest = Join-Path $target ([string]$entry.executable)
    Copy-Item -LiteralPath $exe.FullName -Destination $dest -Force

    $versionRun = & $dest --version 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Version self-test failed for $name" }
    Write-Host "$name staged and verified: $actual :: $versionRun"
  }

  $marker = [ordered]@{
    schemaVersion = '1.0.0'
    source = 'engine-lock.json'
    engines = [ordered]@{
      yaraX = [ordered]@{ version = [string]$lock.engines.yaraX.version; executable = 'yr.exe' }
      capa = [ordered]@{ version = [string]$lock.engines.capa.version; executable = 'capa.exe' }
      floss = [ordered]@{ version = [string]$lock.engines.floss.version; executable = 'floss.exe' }
    }
  }
  $marker | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $target 'ENGINE-BUNDLE.json') -Encoding utf8
  Write-Host 'Pinned multi-engine bundle staged successfully.'
} finally {
  Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
