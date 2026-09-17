param(
  [Parameter(Mandatory=$true)][string]$PackageRoot,
  [Parameter(Mandatory=$true)][ValidateSet('x64','arm64')][string]$Architecture,
  [Parameter(Mandatory=$true)][string]$OutputPath
)

$ErrorActionPreference = 'Stop'
$package = (Resolve-Path -LiteralPath $PackageRoot).Path
$output = [IO.Path]::GetFullPath($OutputPath)

foreach ($required in @('MalGuard.exe','runtime\node.exe','PACKAGE-MANIFEST.json','SHA256SUMS.txt','desktop-app\integrity\preload.js','desktop-app\server.js')) {
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

  $installer = @'
$ErrorActionPreference = 'Stop'
$payload = Join-Path $PSScriptRoot 'payload.zip'
$programs = Join-Path $env:LOCALAPPDATA 'Programs'
$target = Join-Path $programs 'MalGuard'
$stage = Join-Path $programs ('MalGuard.install.' + [guid]::NewGuid().ToString('N'))
$backup = Join-Path $programs 'MalGuard.previous'
New-Item -ItemType Directory -Path $programs -Force | Out-Null
try {
  Expand-Archive -LiteralPath $payload -DestinationPath $stage -Force
  foreach ($required in @('MalGuard.exe','runtime\node.exe','PACKAGE-MANIFEST.json','SHA256SUMS.txt','desktop-app\integrity\preload.js','desktop-app\server.js')) {
    if (-not (Test-Path -LiteralPath (Join-Path $stage $required) -PathType Leaf)) { throw "Payload verification failed: $required" }
  }

  $installedNode = Join-Path $target 'runtime\node.exe'
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
  $shortcut = $shell.CreateShortcut((Join-Path $startMenu 'MalGuard.lnk'))
  $shortcut.TargetPath = Join-Path $target 'MalGuard.exe'
  $shortcut.WorkingDirectory = $target
  $shortcut.Description = 'MalGuard Security Scanner'
  $shortcut.Save()

  if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup -Recurse -Force }
  Start-Process -FilePath (Join-Path $target 'MalGuard.exe') -WorkingDirectory $target
} catch {
  if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue }
  if ((-not (Test-Path -LiteralPath $target)) -and (Test-Path -LiteralPath $backup)) {
    Move-Item -LiteralPath $backup -Destination $target -ErrorAction SilentlyContinue
  }
  throw
}
'@
  $installPath = Join-Path $work 'install.ps1'
  Set-Content -LiteralPath $installPath -Value $installer -Encoding UTF8

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
  & $iexpress /N /Q /M $sed
  if ($LASTEXITCODE -ne 0) { throw "IExpress failed with exit code $LASTEXITCODE" }
  if (-not (Test-Path -LiteralPath $output -PathType Leaf)) { throw 'IExpress did not produce the requested Setup executable.' }
  $size = (Get-Item -LiteralPath $output).Length
  if ($size -lt 65536) { throw "Setup executable is unexpectedly small: $size bytes" }
  Write-Host "Windows installer created: $output ($size bytes)"
} finally {
  Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
