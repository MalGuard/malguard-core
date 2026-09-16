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

function Get-RecentFiles([datetime]$Since, [string]$Root) {
  if (-not $Root -or -not (Test-Path -LiteralPath $Root)) { return @() }
  try {
    return @(Get-ChildItem -LiteralPath $Root -File -Recurse -Force -ErrorAction SilentlyContinue |
      Where-Object { $_.LastWriteTimeUtc -ge $Since.ToUniversalTime() } |
      Select-Object -First 300 FullName, Length, LastWriteTimeUtc)
  } catch { return @() }
}

function Get-ModuleSnapshot([int]$ProcessId) {
  try {
    $p = Get-Process -Id $ProcessId -ErrorAction Stop
    return @($p.Modules | Select-Object @{N='ModuleName';E={$_.ModuleName}}, @{N='FileName';E={$_.FileName}})
  } catch { return @() }
}

function Test-ModuleLoaded([array]$Modules, [string]$Sample) {
  $target = [IO.Path]::GetFullPath($Sample)
  foreach ($module in $Modules) {
    try {
      if ($module.FileName -and ([IO.Path]::GetFullPath([string]$module.FileName) -ieq $target)) { return $true }
    } catch {}
  }
  return $false
}

$result = [ordered]@{
  schemaVersion = '1.1.0'
  sessionId = $SessionId
  startedAt = $started.ToUniversalTime().ToString('o')
  samplePath = $SamplePath
  networkPolicy = 'disabled-by-processcontainer'
  execution = [ordered]@{ attempted = $false; started = $false; exitCode = $null; timedOut = $false; cpuBudgetExceeded = $false; outputQuotaExceeded = $false; error = $null }
  baselineProcesses = @()
  finalProcesses = @()
  recentFiles = @()
  gameContext = [ordered]@{
    enabled = $true
    realGame = $true
    fixtureStarted = $false
    containment = 'processcontainer'
    requiresNestedVirtualization = $false
    hostGameReadOnly = $true
    ephemeralGameClone = $true
    processId = $null
    processName = $null
    executable = $GameExecutable
    baselineModules = @()
    finalModules = @()
    pluginObserved = $false
    startupError = $null
  }
}

$gameProc = $null
$sampleProc = $null
try {
  if (-not (Test-Path -LiteralPath $GameExecutable -PathType Leaf)) { throw 'runtime GTA executable missing' }
  if (-not (Test-Path -LiteralPath $SamplePath -PathType Leaf)) { throw 'staged sample missing' }

  $gameWorkingDirectory = Split-Path -Parent $GameExecutable
  $result.baselineProcesses = @(Get-ProcessSnapshot)
  try {
    $gameProc = Start-Process -FilePath $GameExecutable -WorkingDirectory $gameWorkingDirectory -PassThru
  } catch {
    $result.gameContext.startupError = $_.Exception.Message
    throw 'real GTA process failed to launch in ProcessContainer'
  }

  $gameDeadline = (Get-Date).AddSeconds([Math]::Max(3,$GameStartupSeconds))
  $gameAlive = $false
  while ((Get-Date) -lt $gameDeadline) {
    Start-Sleep -Milliseconds 500
    try {
      $gameProc.Refresh()
      if (-not $gameProc.HasExited) { $gameAlive = $true; break }
    } catch {}
  }
  try { $gameProc.Refresh() } catch {}
  if (-not $gameAlive -or $gameProc.HasExited) {
    $code = $null
    try { $code = $gameProc.ExitCode } catch {}
    $result.gameContext.startupError = "GTA exited before observation. ExitCode=$code"
    throw 'real GTA context did not remain active'
  }

  $result.gameContext.fixtureStarted = $true
  $result.gameContext.processId = $gameProc.Id
  $result.gameContext.processName = $gameProc.ProcessName
  $result.gameContext.baselineModules = @(Get-ModuleSnapshot $gameProc.Id)

  $ext = [IO.Path]::GetExtension($SamplePath).ToLowerInvariant()
  $pluginTypes = @('.asi','.dll')
  $execTypes = @('.exe','.com','.scr','.bat','.cmd','.ps1','.vbs','.js')
  if (($pluginTypes -notcontains $ext) -and ($execTypes -notcontains $ext)) { throw "unsupported GTA behavioral type: $ext" }

  $result.execution.attempted = $true
  if ($pluginTypes -contains $ext) {
    $deadline = (Get-Date).AddSeconds([Math]::Max(3,$ObserveSeconds))
    while ((Get-Date) -lt $deadline) {
      Start-Sleep -Milliseconds 500
      try { $gameProc.Refresh() } catch {}
      if ($gameProc.HasExited) { break }
      $modules = @(Get-ModuleSnapshot $gameProc.Id)
      if (Test-ModuleLoaded $modules $SamplePath) {
        $result.gameContext.pluginObserved = $true
        $result.execution.started = $true
        break
      }
    }
  } else {
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
        if ($gameProc.HasExited -or $sampleProc.HasExited) { break }
      }
      try { $sampleProc.Refresh() } catch {}
      if (-not $sampleProc.HasExited) {
        $result.execution.timedOut = $true
        try { & taskkill.exe /PID $sampleProc.Id /T /F | Out-Null } catch {}
      } else {
        $result.execution.exitCode = $sampleProc.ExitCode
      }
    }
  }

  if ($gameProc -and -not $gameProc.HasExited) {
    $result.gameContext.finalModules = @(Get-ModuleSnapshot $gameProc.Id)
    if (($pluginTypes -contains $ext) -and (-not $result.gameContext.pluginObserved)) {
      $result.gameContext.pluginObserved = Test-ModuleLoaded $result.gameContext.finalModules $SamplePath
      if ($result.gameContext.pluginObserved) { $result.execution.started = $true }
    }
  }
} catch {
  if (-not $result.execution.error) { $result.execution.error = $_.Exception.Message }
} finally {
  $result.finalProcesses = @(Get-ProcessSnapshot)
  $runtimeRoot = Split-Path -Parent (Split-Path -Parent $SamplePath)
  $result.recentFiles = @(Get-RecentFiles $started $runtimeRoot)
  $result.finishedAt = (Get-Date).ToUniversalTime().ToString('o')

  if ($sampleProc) {
    try { $sampleProc.Refresh() } catch {}
    try { if (-not $sampleProc.HasExited) { & taskkill.exe /PID $sampleProc.Id /T /F | Out-Null } } catch {}
  }
  if ($gameProc) {
    try { $gameProc.Refresh() } catch {}
    try { if (-not $gameProc.HasExited) { & taskkill.exe /PID $gameProc.Id /T /F | Out-Null } } catch {}
  }

  $parent = Split-Path -Parent $OutputPath
  New-Item -ItemType Directory -Path $parent -Force | Out-Null
  $tempOutput = "$OutputPath.tmp"
  $result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $tempOutput -Encoding UTF8
  Move-Item -LiteralPath $tempOutput -Destination $OutputPath -Force
}
