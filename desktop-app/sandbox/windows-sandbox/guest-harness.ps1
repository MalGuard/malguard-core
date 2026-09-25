param(
  [Parameter(Mandatory=$true)][string]$SamplePath,
  [Parameter(Mandatory=$true)][string]$OutputPath,
  [Parameter(Mandatory=$true)][string]$SessionId,
  [int]$ObserveSeconds = 8
)

$ErrorActionPreference = 'Stop'
$started = Get-Date

function Get-ProcessSnapshot {
  Get-Process -ErrorAction SilentlyContinue | Select-Object Id, ProcessName, Path
}

function Get-RecentFiles([datetime]$Since) {
  $roots = @($env:TEMP, $env:USERPROFILE, 'C:\Windows\Temp', $env:MALGUARD_GTA_ROOT) |
    Where-Object { $_ -and (Test-Path $_) }
  $rows = @()
  foreach ($root in $roots) {
    try {
      $rows += Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTimeUtc -ge $Since.ToUniversalTime() } |
        Select-Object -First 200 FullName, Length, LastWriteTimeUtc
    } catch {}
  }
  return $rows | Select-Object -First 300
}

$result = [ordered]@{
  schemaVersion = '1.1.0'
  sessionId = $SessionId
  startedAt = $started.ToUniversalTime().ToString('o')
  samplePath = $SamplePath
  networkPolicy = 'disabled-by-wsb'
  execution = [ordered]@{ attempted = $false; started = $false; exitCode = $null; timedOut = $false; cpuBudgetExceeded = $false; outputQuotaExceeded = $false; error = $null }
  baselineProcesses = @(Get-ProcessSnapshot)
  finalProcesses = @()
  recentFiles = @()
}

$pluginLoaderScript = $null

try {
  if (-not (Test-Path -LiteralPath $SamplePath -PathType Leaf)) { throw 'sample missing in sandbox input' }
  $ext = [IO.Path]::GetExtension($SamplePath).ToLowerInvariant()
  $allowed = @('.exe','.com','.scr','.bat','.cmd','.ps1','.vbs','.js','.asi','.dll')
  if ($allowed -notcontains $ext) { throw "unsupported behavioral execution type: $ext" }

  $executionPath = $SamplePath
  if ($ext -eq '.asi' -or $ext -eq '.dll') {
    $simulationRoot = 'C:\MalGuardGtaSim'
    $gameRoot = Join-Path $simulationRoot 'Game'
    $pluginRoot = Join-Path $gameRoot 'plugins'
    $scriptRoot = Join-Path $gameRoot 'scripts'
    New-Item -ItemType Directory -Path $pluginRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $scriptRoot -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $gameRoot 'GTA5.exe.simulated') -Value 'MalGuard synthetic GTA runtime marker. Not a real game executable.' -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $pluginRoot 'README.txt') -Value 'Disposable GTA plugin simulation directory.' -Encoding UTF8

    $executionPath = Join-Path $pluginRoot ('sample' + $ext)
    Copy-Item -LiteralPath $SamplePath -Destination $executionPath -Force

    $env:MALGUARD_GTA_SIM = '1'
    $env:MALGUARD_GTA_ROOT = $gameRoot
    $env:MALGUARD_GTA_PLUGIN_ROOT = $pluginRoot
    $env:MALGUARD_GTA_SCRIPT_ROOT = $scriptRoot

    $pluginLoaderScript = Join-Path $env:TEMP ('malguard-gta-plugin-loader-' + $SessionId + '.ps1')
    @'
param([Parameter(Mandatory=$true)][string]$PluginPath,[int]$HoldSeconds=8)
$ErrorActionPreference='Stop'
$source=@"
using System;
using System.Runtime.InteropServices;
public static class MalGuardGtaPluginLoader {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern IntPtr LoadLibraryW(string lpFileName);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool FreeLibrary(IntPtr hModule);
}
"@
Add-Type -TypeDefinition $source -Language CSharp
$module=[MalGuardGtaPluginLoader]::LoadLibraryW($PluginPath)
if($module -eq [IntPtr]::Zero){ exit 111 }
try { Start-Sleep -Seconds ([Math]::Max(1,[Math]::Min(30,$HoldSeconds))) }
finally { [MalGuardGtaPluginLoader]::FreeLibrary($module) | Out-Null }
exit 0
'@ | Set-Content -LiteralPath $pluginLoaderScript -Encoding UTF8
  }

  $result.execution.attempted = $true
  $proc = $null
  $quotedExecutionPath = '"' + $executionPath + '"'
  switch ($ext) {
    '.exe' { $proc = Start-Process -FilePath $executionPath -PassThru -WindowStyle Hidden }
    '.com' { $proc = Start-Process -FilePath $executionPath -PassThru -WindowStyle Hidden }
    '.scr' { $proc = Start-Process -FilePath $executionPath -PassThru -WindowStyle Hidden }
    '.bat' { $proc = Start-Process -FilePath 'cmd.exe' -ArgumentList @('/d','/c',$quotedExecutionPath) -PassThru -WindowStyle Hidden }
    '.cmd' { $proc = Start-Process -FilePath 'cmd.exe' -ArgumentList @('/d','/c',$quotedExecutionPath) -PassThru -WindowStyle Hidden }
    '.ps1' { $proc = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','RemoteSigned','-File',$quotedExecutionPath) -PassThru -WindowStyle Hidden }
    '.vbs' { $proc = Start-Process -FilePath 'cscript.exe' -ArgumentList @('//Nologo',$quotedExecutionPath) -PassThru -WindowStyle Hidden }
    '.js' { $proc = Start-Process -FilePath 'cscript.exe' -ArgumentList @('//Nologo',$quotedExecutionPath) -PassThru -WindowStyle Hidden }
    '.asi' {
      $quotedLoader = '"' + $pluginLoaderScript + '"'
      $proc = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','RemoteSigned','-File',$quotedLoader,'-PluginPath',$quotedExecutionPath,'-HoldSeconds',[string]$ObserveSeconds) -PassThru -WindowStyle Hidden
    }
    '.dll' {
      $quotedLoader = '"' + $pluginLoaderScript + '"'
      $proc = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','RemoteSigned','-File',$quotedLoader,'-PluginPath',$quotedExecutionPath,'-HoldSeconds',[string]$ObserveSeconds) -PassThru -WindowStyle Hidden
    }
  }
  if ($proc) {
    $result.execution.started = $true
    $deadline = (Get-Date).AddSeconds([Math]::Max(1,$ObserveSeconds))
    while (-not $proc.HasExited -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 200; $proc.Refresh() }
    if (-not $proc.HasExited) {
      $result.execution.timedOut = $true
      & taskkill.exe /PID $proc.Id /T /F | Out-Null
    } else {
      $result.execution.exitCode = $proc.ExitCode
    }
  }
} catch {
  $result.execution.error = $_.Exception.Message
} finally {
  if ($pluginLoaderScript -and (Test-Path -LiteralPath $pluginLoaderScript)) {
    Remove-Item -LiteralPath $pluginLoaderScript -Force -ErrorAction SilentlyContinue
  }
}

$result.finalProcesses = @(Get-ProcessSnapshot)
$result.recentFiles = @(Get-RecentFiles $started)
$result.finishedAt = (Get-Date).ToUniversalTime().ToString('o')

$parent = Split-Path -Parent $OutputPath
New-Item -ItemType Directory -Path $parent -Force | Out-Null
$result | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
