param(
  [Parameter(Mandatory=$true)][string]$SamplePath,
  [Parameter(Mandatory=$true)][string]$GameExecutable,
  [Parameter(Mandatory=$true)][string]$OutputPath,
  [Parameter(Mandatory=$true)][string]$SessionId,
  [int]$ObserveSeconds = 12,
  [int]$GameStartupSeconds = 20
)

$ErrorActionPreference = 'Stop'
$started = Get-Date

function Get-ProcessSnapshot {
  Get-Process -ErrorAction SilentlyContinue | Select-Object Id, ProcessName, Path
}

function Get-RecentFiles([datetime]$Since) {
  $roots = @($env:TEMP, $env:USERPROFILE, 'C:\Windows\Temp') | Where-Object { $_ -and (Test-Path $_) }
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

function Get-ModuleSnapshot([int]$ProcessId) {
  try {
    $p = Get-Process -Id $ProcessId -ErrorAction Stop
    return @($p.Modules | Select-Object @{N='ModuleName';E={$_.ModuleName}}, @{N='FileName';E={$_.FileName}})
  } catch {
    return @()
  }
}

$result = [ordered]@{
  schemaVersion = '1.1.0'
  sessionId = $SessionId
  startedAt = $started.ToUniversalTime().ToString('o')
  samplePath = $SamplePath
  networkPolicy = 'disabled-by-wsb'
  execution = [ordered]@{ attempted = $false; started = $false; exitCode = $null; timedOut = $false; cpuBudgetExceeded = $false; outputQuotaExceeded = $false; error = $null }
  baselineProcesses = @()
  finalProcesses = @()
  recentFiles = @()
  gameContext = [ordered]@{
    enabled = $true
    realGame = $true
    fixtureStarted = $false
    processId = $null
    processName = $null
    executable = $GameExecutable
    baselineModules = @()
    finalModules = @()
    startupError = $null
  }
}

$gameProc = $null
$sampleProc = $null
try {
  if (-not (Test-Path -LiteralPath $GameExecutable -PathType Leaf)) { throw 'real GTA executable missing inside sandbox mapping' }
  if (-not (Test-Path -LiteralPath $SamplePath -PathType Leaf)) { throw 'sample missing inside sandbox input' }

  $gameWorkingDirectory = Split-Path -Parent $GameExecutable
  try {
    $gameProc = Start-Process -FilePath $GameExecutable -WorkingDirectory $gameWorkingDirectory -PassThru
  } catch {
    $result.gameContext.startupError = $_.Exception.Message
    throw 'real GTA process failed to launch'
  }

  $gameDeadline = (Get-Date).AddSeconds([Math]::Max(3,$GameStartupSeconds))
  while ((Get-Date) -lt $gameDeadline) {
    Start-Sleep -Milliseconds 500
    try {
      $gameProc.Refresh()
      if (-not $gameProc.HasExited) { break }
    } catch {}
  }
  $gameProc.Refresh()
  if ($gameProc.HasExited) {
    $result.gameContext.startupError = "GTA exited before behavioral observation. ExitCode=$($gameProc.ExitCode)"
    throw 'real GTA context did not remain active'
  }

  $result.gameContext.fixtureStarted = $true
  $result.gameContext.processId = $gameProc.Id
  $result.gameContext.processName = $gameProc.ProcessName
  $result.gameContext.baselineModules = @(Get-ModuleSnapshot $gameProc.Id)
  $result.baselineProcesses = @(Get-ProcessSnapshot)

  $ext = [IO.Path]::GetExtension($SamplePath).ToLowerInvariant()
  $allowed = @('.exe','.com','.scr','.bat','.cmd','.ps1','.vbs','.js')
  if ($allowed -notcontains $ext) { throw "unsupported behavioral execution type in GTA context: $ext" }

  $result.execution.attempted = $true
  switch ($ext) {
    '.exe' { $sampleProc = Start-Process -FilePath $SamplePath -PassThru -WindowStyle Hidden }
    '.com' { $sampleProc = Start-Process -FilePath $SamplePath -PassThru -WindowStyle Hidden }
    '.scr' { $sampleProc = Start-Process -FilePath $SamplePath -PassThru -WindowStyle Hidden }
    '.bat' { $sampleProc = Start-Process -FilePath 'cmd.exe' -ArgumentList @('/d','/c',"`"$SamplePath`"") -PassThru -WindowStyle Hidden }
    '.cmd' { $sampleProc = Start-Process -FilePath 'cmd.exe' -ArgumentList @('/d','/c',"`"$SamplePath`"") -PassThru -WindowStyle Hidden }
    '.ps1' { $sampleProc = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','RemoteSigned','-File',"`"$SamplePath`"") -PassThru -WindowStyle Hidden }
    '.vbs' { $sampleProc = Start-Process -FilePath 'cscript.exe' -ArgumentList @('//Nologo',"`"$SamplePath`"") -PassThru -WindowStyle Hidden }
    '.js' { $sampleProc = Start-Process -FilePath 'cscript.exe' -ArgumentList @('//Nologo',"`"$SamplePath`"") -PassThru -WindowStyle Hidden }
  }

  if ($sampleProc) {
    $result.execution.started = $true
    $deadline = (Get-Date).AddSeconds([Math]::Max(3,$ObserveSeconds))
    while ((Get-Date) -lt $deadline) {
      Start-Sleep -Milliseconds 250
      try { $sampleProc.Refresh() } catch {}
      try { $gameProc.Refresh() } catch {}
      if ($gameProc.HasExited) {
        $result.gameContext.startupError = 'GTA process exited during sample observation'
        break
      }
    }
    if (-not $sampleProc.HasExited) {
      $result.execution.timedOut = $true
      & taskkill.exe /PID $sampleProc.Id /T /F | Out-Null
    } else {
      $result.execution.exitCode = $sampleProc.ExitCode
    }
  }

  $result.gameContext.finalModules = @(Get-ModuleSnapshot $gameProc.Id)
} catch {
  if (-not $result.execution.error) { $result.execution.error = $_.Exception.Message }
} finally {
  $result.finalProcesses = @(Get-ProcessSnapshot)
  $result.recentFiles = @(Get-RecentFiles $started)
  $result.finishedAt = (Get-Date).ToUniversalTime().ToString('o')

  if ($sampleProc -and -not $sampleProc.HasExited) {
    try { & taskkill.exe /PID $sampleProc.Id /T /F | Out-Null } catch {}
  }
  if ($gameProc -and -not $gameProc.HasExited) {
    try { & taskkill.exe /PID $gameProc.Id /T /F | Out-Null } catch {}
  }

  $parent = Split-Path -Parent $OutputPath
  New-Item -ItemType Directory -Path $parent -Force | Out-Null
  $tempOutput = "$OutputPath.tmp"
  $result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $tempOutput -Encoding UTF8
  Move-Item -LiteralPath $tempOutput -Destination $OutputPath -Force
}
