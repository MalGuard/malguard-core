param(
  [Parameter(Mandatory=$true)][string]$SamplePath,
  [Parameter(Mandatory=$true)][string]$GameSourceRoot,
  [Parameter(Mandatory=$true)][string]$GameExecutableRelative,
  [Parameter(Mandatory=$true)][string]$OutputPath,
  [Parameter(Mandatory=$true)][string]$SessionId,
  [int]$ObserveSeconds = 12,
  [int]$GameStartupSeconds = 20,
  [int]$GamePrepareSeconds = 900
)

$ErrorActionPreference = 'Stop'
$started = Get-Date

function Get-ProcessSnapshot {
  Get-Process -ErrorAction SilentlyContinue | Select-Object Id, ProcessName, Path
}

function Get-RecentFiles([datetime]$Since) {
  $roots = @($env:TEMP, $env:USERPROFILE, 'C:\Windows\Temp', 'C:\MalGuardRuntime') | Where-Object { $_ -and (Test-Path $_) }
  $rows = @()
  foreach ($root in $roots) {
    try {
      $rows += Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTimeUtc -ge $Since.ToUniversalTime() } |
        Select-Object -First 250 FullName, Length, LastWriteTimeUtc
    } catch {}
  }
  return $rows | Select-Object -First 400
}

function Get-ModuleSnapshot([int]$ProcessId) {
  try {
    $p = Get-Process -Id $ProcessId -ErrorAction Stop
    return @($p.Modules | Select-Object @{N='ModuleName';E={$_.ModuleName}}, @{N='FileName';E={$_.FileName}})
  } catch {
    return @()
  }
}

function Test-ModuleLoaded([object[]]$Modules, [string]$ExpectedPath, [string]$ExpectedName) {
  $targetPath = [IO.Path]::GetFullPath($ExpectedPath)
  foreach ($module in @($Modules)) {
    try {
      if ($module.FileName -and ([IO.Path]::GetFullPath([string]$module.FileName) -ieq $targetPath)) { return $true }
    } catch {}
    if ($module.ModuleName -and ([string]$module.ModuleName -ieq $ExpectedName)) { return $true }
  }
  return $false
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
    executable = $null
    sourceRoot = $GameSourceRoot
    runtimeRoot = 'C:\MalGuardRuntime\Game'
    stagingMode = 'sandbox-local-full-copy'
    hostGameReadOnly = $true
    pluginMode = $false
    stagedPlugin = $null
    pluginLoadProven = $false
    baselineModules = @()
    finalModules = @()
    startupError = $null
    preparationError = $null
  }
}

$gameProc = $null
$sampleProc = $null
try {
  if (-not (Test-Path -LiteralPath $GameSourceRoot -PathType Container)) { throw 'real GTA source root missing inside sandbox mapping' }
  if (-not (Test-Path -LiteralPath $SamplePath -PathType Leaf)) { throw 'sample missing inside sandbox input' }

  $runtimeRoot = 'C:\MalGuardRuntime\Game'
  New-Item -ItemType Directory -Path $runtimeRoot -Force | Out-Null

  $prepareDeadline = (Get-Date).AddSeconds([Math]::Max(60,$GamePrepareSeconds))
  $copy = Start-Process -FilePath 'robocopy.exe' -ArgumentList @(
    $GameSourceRoot,
    $runtimeRoot,
    '/E','/COPY:DAT','/DCOPY:DAT','/R:1','/W:1','/XJ','/SL','/NFL','/NDL','/NJH','/NJS','/NP'
  ) -PassThru -WindowStyle Hidden
  while (-not $copy.HasExited -and (Get-Date) -lt $prepareDeadline) {
    Start-Sleep -Milliseconds 500
    try { $copy.Refresh() } catch {}
  }
  if (-not $copy.HasExited) {
    try { & taskkill.exe /PID $copy.Id /T /F | Out-Null } catch {}
    $result.gameContext.preparationError = 'GTA sandbox-local clone preparation timed out'
    throw 'GTA runtime clone preparation timed out'
  }
  if ($copy.ExitCode -ge 8) {
    $result.gameContext.preparationError = "robocopy failed with exit code $($copy.ExitCode)"
    throw 'GTA runtime clone preparation failed'
  }

  $relative = $GameExecutableRelative.Replace('/','\').TrimStart('\')
  if ($relative -match '(^|\\)\.\.(\\|$)') { throw 'GTA executable relative path traversal rejected' }
  $GameExecutable = Join-Path $runtimeRoot $relative
  if (-not (Test-Path -LiteralPath $GameExecutable -PathType Leaf)) { throw 'real GTA executable missing from sandbox-local clone' }
  $result.gameContext.executable = $GameExecutable

  $ext = [IO.Path]::GetExtension($SamplePath).ToLowerInvariant()
  $processAllowed = @('.exe','.com','.scr','.bat','.cmd','.ps1','.vbs','.js')
  $pluginAllowed = @('.asi','.dll')
  if (($processAllowed -notcontains $ext) -and ($pluginAllowed -notcontains $ext)) {
    throw "unsupported behavioral execution type in GTA context: $ext"
  }

  $gameWorkingDirectory = Split-Path -Parent $GameExecutable
  if ($pluginAllowed -contains $ext) {
    $result.gameContext.pluginMode = $true
    $stagedPlugin = Join-Path $gameWorkingDirectory ("malguard-sample" + $ext)
    Copy-Item -LiteralPath $SamplePath -Destination $stagedPlugin -Force
    $result.gameContext.stagedPlugin = $stagedPlugin
    $result.execution.attempted = $true
  }

  $result.baselineProcesses = @(Get-ProcessSnapshot)
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

  if ($pluginAllowed -contains $ext) {
    $pluginPath = [string]$result.gameContext.stagedPlugin
    $pluginName = Split-Path -Leaf $pluginPath
    $pluginDeadline = (Get-Date).AddSeconds([Math]::Max(3,$ObserveSeconds))
    while ((Get-Date) -lt $pluginDeadline) {
      Start-Sleep -Milliseconds 250
      try { $gameProc.Refresh() } catch {}
      if ($gameProc.HasExited) {
        $result.gameContext.startupError = 'GTA process exited during plugin observation'
        break
      }
      $mods = @(Get-ModuleSnapshot $gameProc.Id)
      if (Test-ModuleLoaded $mods $pluginPath $pluginName) {
        $result.execution.started = $true
        $result.gameContext.pluginLoadProven = $true
        break
      }
    }
  } else {
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
