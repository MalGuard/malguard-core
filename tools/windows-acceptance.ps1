[CmdletBinding()]
param(
  [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot),
  [string]$ReportPath = "",
  [switch]$SkipRegression
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function New-Check([string]$Name) {
  return [ordered]@{ name = $Name; pass = $false; detail = $null }
}

function Invoke-CheckedProcess {
  param(
    [Parameter(Mandatory=$true)][string]$FilePath,
    [Parameter(Mandatory=$false)][string[]]$ArgumentList = @(),
    [Parameter(Mandatory=$true)][string]$WorkingDirectory,
    [int]$ExpectedExitCode = 0,
    [int]$TimeoutSeconds = 180
  )
  $stdout = [System.IO.Path]::GetTempFileName()
  $stderr = [System.IO.Path]::GetTempFileName()
  try {
    $p = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -WorkingDirectory $WorkingDirectory -NoNewWindow -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    if (-not $p.WaitForExit($TimeoutSeconds * 1000)) {
      # Kill only the synthetic validation process tree started by this harness.
      & taskkill.exe /PID $p.Id /T /F *> $null
      throw "process timeout: $FilePath exceeded ${TimeoutSeconds}s"
    }
    $p.WaitForExit()
    $out = Get-Content -LiteralPath $stdout -Raw -ErrorAction SilentlyContinue
    $err = Get-Content -LiteralPath $stderr -Raw -ErrorAction SilentlyContinue
    if ($p.ExitCode -ne $ExpectedExitCode) {
      throw "process failed: $FilePath exit=$($p.ExitCode) expected=$ExpectedExitCode`n$out`n$err"
    }
    return [ordered]@{ exitCode = $p.ExitCode; stdout = $out; stderr = $err }
  } finally {
    Remove-Item -LiteralPath $stdout,$stderr -Force -ErrorAction SilentlyContinue
  }
}

function Configure-And-Build {
  param(
    [Parameter(Mandatory=$true)][string]$SourceDir,
    [Parameter(Mandatory=$true)][string]$BuildDir,
    [Parameter(Mandatory=$true)][string]$ExeName,
    [Parameter(Mandatory=$true)][string]$ProjectRoot
  )
  New-Item -ItemType Directory -Path $BuildDir -Force | Out-Null
  $configured = $false
  try {
    Invoke-CheckedProcess -FilePath 'cmake.exe' -ArgumentList @('-S', $SourceDir, '-B', $BuildDir, '-A', 'x64') -WorkingDirectory $ProjectRoot | Out-Null
    $configured = $true
  } catch {
    # Some environments use Ninja or a compiler shell where -A is invalid.
    Remove-Item -LiteralPath $BuildDir -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Path $BuildDir -Force | Out-Null
    Invoke-CheckedProcess -FilePath 'cmake.exe' -ArgumentList @('-S', $SourceDir, '-B', $BuildDir, '-DCMAKE_BUILD_TYPE=Release') -WorkingDirectory $ProjectRoot | Out-Null
    $configured = $true
  }
  if (-not $configured) { throw 'CMake configuration did not complete' }
  Invoke-CheckedProcess -FilePath 'cmake.exe' -ArgumentList @('--build', $BuildDir, '--config', 'Release') -WorkingDirectory $ProjectRoot | Out-Null
  $exe = Get-ChildItem -LiteralPath $BuildDir -Filter $ExeName -File -Recurse | Select-Object -First 1
  if (-not $exe) { throw "$ExeName was not produced by the build" }
  return $exe.FullName
}

$root = (Resolve-Path -LiteralPath $ProjectRoot).Path
if ([string]::IsNullOrWhiteSpace($ReportPath)) {
  $ReportPath = Join-Path $root 'windows-acceptance-report.json'
} else {
  $ReportPath = [System.IO.Path]::GetFullPath($ReportPath)
}

$report = [ordered]@{
  schemaVersion = '1.0.0'
  kind = 'malguard-windows-acceptance'
  phase = 'sandbox-native-build-and-isolation'
  startedAt = (Get-Date).ToUniversalTime().ToString('o')
  completedAt = $null
  host = [ordered]@{
    os = [System.Environment]::OSVersion.VersionString
    is64BitOperatingSystem = [System.Environment]::Is64BitOperatingSystem
    powershell = $PSVersionTable.PSVersion.ToString()
  }
  safety = [ordered]@{
    untrustedSamplesExecuted = $false
    serviceInstalled = $false
    systemConfigurationChanged = $false
    note = 'This harness compiles native components and runs synthetic containment/isolation self-tests only.'
  }
  checks = @()
  blockers = @()
  pass = $false
}

try {
  $check = New-Check 'windows_host'
  if ($env:OS -ne 'Windows_NT') { throw 'Windows host required' }
  $check.pass = $true
  $check.detail = $report.host.os
  $report.checks += $check

  foreach ($command in @('node.exe','cmake.exe')) {
    $check = New-Check "tool_$command"
    $cmd = Get-Command $command -ErrorAction Stop
    $check.pass = $true
    $check.detail = $cmd.Source
    $report.checks += $check
  }

  if (-not $SkipRegression) {
    $check = New-Check 'full_regression_suite'
    try {
      $reg = Invoke-CheckedProcess -FilePath 'node.exe' -ArgumentList @('tests/run-all.js') -WorkingDirectory $root -TimeoutSeconds 300
      $check.pass = $true
      $check.detail = (($reg.stdout -split "`r?`n") | Select-Object -Last 3) -join "`n"
    } catch {
      $check.detail = $_.Exception.Message
      $report.checks += $check
      throw
    }
    $report.checks += $check
  }

  $buildRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("malguard-win-acceptance-" + [Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $buildRoot -Force | Out-Null
  try {
    $check = New-Check 'containment_probe_build'
    try {
      $probeExe = Configure-And-Build -SourceDir (Join-Path $root 'native/sandbox-containment-probe') -BuildDir (Join-Path $buildRoot 'containment') -ExeName 'MalGuardSandboxContainmentProbe.exe' -ProjectRoot $root
      $check.pass = $true
      $check.detail = $probeExe
    } catch {
      $check.detail = $_.Exception.Message
      $report.checks += $check
      throw
    }
    $report.checks += $check

    $check = New-Check 'windows_service_build'
    try {
      $serviceExe = Configure-And-Build -SourceDir (Join-Path $root 'native/windows-service') -BuildDir (Join-Path $buildRoot 'service') -ExeName 'MalGuardService.exe' -ProjectRoot $root
      $check.pass = $true
      $check.detail = $serviceExe
    } catch {
      $check.detail = $_.Exception.Message
      $report.checks += $check
      throw
    }
    $report.checks += $check

    $check = New-Check 'sandbox_native_acceptance'
    $sandboxReportPath = Join-Path $buildRoot 'sandbox-acceptance.json'
    try {
      $runner = Invoke-CheckedProcess -FilePath 'node.exe' -ArgumentList @('tools/windows-acceptance-runner.js','--probe',$probeExe,'--report',$sandboxReportPath) -WorkingDirectory $root -TimeoutSeconds 60
      $sandbox = Get-Content -LiteralPath $sandboxReportPath -Raw | ConvertFrom-Json
      $check.pass = ($sandbox.pass -eq $true)
      $check.detail = $sandbox
      if (-not $check.pass) { throw 'Sandbox native acceptance did not reach releaseReady=true' }
    } catch {
      if (Test-Path -LiteralPath $sandboxReportPath) {
        $check.detail = Get-Content -LiteralPath $sandboxReportPath -Raw | ConvertFrom-Json
      } elseif (-not $check.detail) {
        $check.detail = $_.Exception.Message
      }
      $report.checks += $check
      throw
    }
    $report.checks += $check
  } finally {
    Remove-Item -LiteralPath $buildRoot -Recurse -Force -ErrorAction SilentlyContinue
  }

  $report.pass = (@($report.checks | Where-Object { $_.pass -ne $true }).Count -eq 0)
} catch {
  $report.blockers += $_.Exception.Message
  $report.pass = $false
} finally {
  $report.completedAt = (Get-Date).ToUniversalTime().ToString('o')
  $json = $report | ConvertTo-Json -Depth 20
  $parent = Split-Path -Parent $ReportPath
  if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
  $tmp = "$ReportPath.$PID.tmp"
  Set-Content -LiteralPath $tmp -Value $json -Encoding UTF8
  Move-Item -LiteralPath $tmp -Destination $ReportPath -Force
  Write-Output $json
}

if (-not $report.pass) { exit 2 }
exit 0
