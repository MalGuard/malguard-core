param(
  [Parameter(Mandatory=$true)][string]$PackageRoot,
  [Parameter(Mandatory=$true)][ValidateSet('x64','arm64')][string]$Architecture,
  [Parameter(Mandatory=$true)][string]$OutputPath,
  [string]$DiagnosticOutputDirectory
)

$ErrorActionPreference = 'Stop'
$package = (Resolve-Path -LiteralPath $PackageRoot).Path
$output = [IO.Path]::GetFullPath($OutputPath)
$launcherRelative = 'desktop-app\bin\MalGuard.exe'
$nodeRelative = 'desktop-app\runtime\node.exe'

foreach ($required in @($launcherRelative,$nodeRelative,'PACKAGE-MANIFEST.json','SHA256SUMS.txt','desktop-app\integrity\preload.js','desktop-app\server.js')) {
  if (-not (Test-Path -LiteralPath (Join-Path $package $required) -PathType Leaf)) {
    throw "Installer package is incomplete: $required"
  }
}

$iexpress = Join-Path $env:SystemRoot 'System32\iexpress.exe'
if (-not (Test-Path -LiteralPath $iexpress -PathType Leaf)) { throw 'IExpress is unavailable on this Windows host.' }

$work = Join-Path $env:RUNNER_TEMP ("malguard-installer-" + $Architecture + '-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work -Force | Out-Null
try {
  $payload = Join-Path $work 'payload.zip'
  Compress-Archive -Path (Join-Path $package '*') -DestinationPath $payload -CompressionLevel Optimal -Force
  $payloadSha256 = (Get-FileHash -LiteralPath $payload -Algorithm SHA256).Hash.ToLowerInvariant()

  $installer = @'
$ErrorActionPreference = 'Stop'
$payload = Join-Path $PSScriptRoot 'payload.zip'
$expectedPayloadSha256 = '__MALGUARD_PAYLOAD_SHA256__'
$programs = Join-Path $env:LOCALAPPDATA 'Programs'
$target = Join-Path $programs 'MalGuard'
$stage = Join-Path $programs ('MalGuard.install.' + [guid]::NewGuid().ToString('N'))
$backup = Join-Path $programs 'MalGuard.previous'
$launcherRelative = 'desktop-app\bin\MalGuard.exe'
$nodeRelative = 'desktop-app\runtime\node.exe'

function Assert-SealedPayload([string]$Root) {
  $manifestPath = Join-Path $Root 'PACKAGE-MANIFEST.json'
  $sumsPath = Join-Path $Root 'SHA256SUMS.txt'
  if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf) -or -not (Test-Path -LiteralPath $sumsPath -PathType Leaf)) {
    throw 'Payload seal is incomplete.'
  }

  $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
  if ($manifest.schemaVersion -ne '1.0.0' -or $manifest.product -ne 'MalGuard Desktop' -or $manifest.entrypoint -ne 'desktop-app/server.js') {
    throw 'Payload manifest identity is invalid.'
  }
  if ([string]$manifest.sourceCommit -notmatch '^(?:[a-f0-9]{40}|[a-f0-9]{64})$') {
    throw 'Payload source provenance is invalid.'
  }
  $fileCount = [int]$manifest.fileCount
  if ($fileCount -lt 3) { throw 'Payload manifest file count is invalid.' }

  $expected = @{}
  foreach ($line in @(Get-Content -LiteralPath $sumsPath)) {
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    if ($line -notmatch '^([a-f0-9]{64})  (.+)$') { throw "Malformed payload checksum entry: $line" }
    $relative = [string]$Matches[2]
    if ($relative -eq 'SHA256SUMS.txt' -or $relative -match '\\' -or $relative.StartsWith('/') -or $relative -match '^[A-Za-z]:' -or $relative -match '(^|/)\.\.(/|$)') {
      throw "Unsafe payload checksum path: $relative"
    }
    if ($expected.ContainsKey($relative)) { throw "Duplicate payload checksum entry: $relative" }
    $expected[$relative] = ([string]$Matches[1]).ToLowerInvariant()
  }
  if (-not $expected.ContainsKey('PACKAGE-MANIFEST.json')) { throw 'Payload manifest is not integrity-covered.' }

  foreach ($dir in @(Get-ChildItem -LiteralPath $Root -Directory -Recurse -Force)) {
    if (($dir.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "Payload contains reparse-point directory: $($dir.FullName)"
    }
  }

  $files = @(Get-ChildItem -LiteralPath $Root -File -Recurse -Force)
  if ($files.Count -ne $fileCount) { throw "Payload file count mismatch: expected $fileCount, got $($files.Count)" }
  if ($expected.Count -ne ($files.Count - 1)) { throw 'Payload checksum coverage mismatch.' }

  foreach ($item in $files) {
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "Payload contains reparse-point file: $($item.FullName)"
    }
    $relative = ($item.FullName.Substring($Root.Length) -replace '^[\\/]+','') -replace '\\','/'
    if ($relative -eq 'SHA256SUMS.txt') { continue }
    if (-not $expected.ContainsKey($relative)) { throw "Unexpected payload file: $relative" }
    $actual = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected[$relative]) { throw "Payload SHA-256 mismatch: $relative" }
  }
}

$actualPayloadSha256 = (Get-FileHash -LiteralPath $payload -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualPayloadSha256 -ne $expectedPayloadSha256) {
  throw 'Installer payload archive integrity mismatch.'
}

New-Item -ItemType Directory -Path $programs -Force | Out-Null
try {
  Expand-Archive -LiteralPath $payload -DestinationPath $stage -Force
  foreach ($required in @($launcherRelative,$nodeRelative,'PACKAGE-MANIFEST.json','SHA256SUMS.txt','desktop-app\integrity\preload.js','desktop-app\server.js')) {
    if (-not (Test-Path -LiteralPath (Join-Path $stage $required) -PathType Leaf)) { throw "Payload verification failed: $required" }
  }
  Assert-SealedPayload $stage

  $installedNode = Join-Path $target $nodeRelative
  try {
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
      Where-Object { $_.ExecutablePath -and [string]::Equals($_.ExecutablePath, $installedNode, [StringComparison]::OrdinalIgnoreCase) } |
      ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
  } catch {}

  if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup -Recurse -Force }
  if (Test-Path -LiteralPath $target) { Move-Item -LiteralPath $target -Destination $backup }
  Move-Item -LiteralPath $stage -Destination $target

  $shell = New-Object -ComObject WScript.Shell
  $startMenu = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'
  New-Item -ItemType Directory -Path $startMenu -Force | Out-Null
  $desktop = $shell.SpecialFolders.Item('Desktop')
  if (-not $desktop -or -not (Test-Path -LiteralPath $desktop -PathType Container)) { throw 'Windows Desktop shortcut folder is unavailable.' }
  foreach ($shortcutPath in @((Join-Path $startMenu 'GTA Guard.lnk'), (Join-Path $desktop 'GTA Guard.lnk'))) {
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = Join-Path $target $launcherRelative
    $shortcut.WorkingDirectory = $target
    $shortcut.Description = 'GTA Guard local scanner'
    $shortcut.Save()
  }

  Start-Process -FilePath (Join-Path $target $launcherRelative) -WorkingDirectory $target
  if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup -Recurse -Force }
} catch {
  if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue }
  if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction SilentlyContinue }
  if (Test-Path -LiteralPath $backup) {
    Move-Item -LiteralPath $backup -Destination $target -ErrorAction SilentlyContinue
  }
  throw
}
'@
  $installer = $installer.Replace('__MALGUARD_PAYLOAD_SHA256__', $payloadSha256)
  $installPath = Join-Path $work 'install.ps1'
  Set-Content -LiteralPath $installPath -Value $installer -Encoding UTF8
  if ($DiagnosticOutputDirectory) {
    New-Item -ItemType Directory -Path $DiagnosticOutputDirectory -Force | Out-Null
    Copy-Item -LiteralPath $payload -Destination (Join-Path $DiagnosticOutputDirectory 'payload.zip') -Force
    Copy-Item -LiteralPath $installPath -Destination (Join-Path $DiagnosticOutputDirectory 'install.ps1') -Force
  }

  $sed = Join-Path $work 'malguard.sed'
  $targetEscaped = $output.Replace('%','%%')
  $sourceEscaped = ($work.TrimEnd('\') + '\').Replace('%','%%')
  $sedText = @"
[Version]
Class=IEXPRESS
SEDVersion=3
[Options]
PackagePurpose=InstallApp
ShowInstallProgramWindow=0
HideExtractAnimation=1
UseLongFileName=1
InsideCompressed=0
CAB_FixedSize=0
CAB_ResvCodeSigning=0
RebootMode=N
InstallPrompt=%InstallPrompt%
DisplayLicense=%DisplayLicense%
FinishMessage=%FinishMessage%
TargetName=%TargetName%
FriendlyName=%FriendlyName%
AppLaunched=%AppLaunched%
PostInstallCmd=%PostInstallCmd%
AdminQuietInstCmd=%AdminQuietInstCmd%
UserQuietInstCmd=%UserQuietInstCmd%
SourceFiles=SourceFiles
[Strings]
InstallPrompt=
DisplayLicense=
FinishMessage=
TargetName=$targetEscaped
FriendlyName=MalGuard Security Scanner ($Architecture)
AppLaunched=powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File install.ps1
PostInstallCmd=<None>
AdminQuietInstCmd=
UserQuietInstCmd=
FILE0="payload.zip"
FILE1="install.ps1"
[SourceFiles]
SourceFiles0=$sourceEscaped
[SourceFiles0]
%FILE0%=
%FILE1%=
"@
  Set-Content -LiteralPath $sed -Value $sedText -Encoding ASCII

  New-Item -ItemType Directory -Path (Split-Path -Parent $output) -Force | Out-Null
  $process = Start-Process -FilePath $iexpress -ArgumentList @('/N','/Q', $sed) -WorkingDirectory $work -Wait -PassThru -NoNewWindow
  if (-not (Test-Path -LiteralPath $output -PathType Leaf)) {
    throw "IExpress did not produce the requested Setup executable (exit $($process.ExitCode))."
  }
  if ($process.ExitCode -ne 0) { throw "IExpress produced a file but reported exit code $($process.ExitCode)" }
  $size = (Get-Item -LiteralPath $output).Length
  if ($size -lt 65536) { throw "Setup executable is unexpectedly small: $size bytes" }
  Write-Host "Windows installer created: $output ($size bytes)"
} finally {
  Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
