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

try {
  if (-not (Test-Path -LiteralPath $SamplePath -PathType Leaf)) { throw 'sample missing in sandbox input' }
  $ext = [IO.Path]::GetExtension($SamplePath).ToLowerInvariant()
  $allowed = @('.exe','.com','.scr','.bat','.cmd','.ps1','.vbs','.js')
  if ($allowed -notcontains $ext) { throw "unsupported behavioral execution type: $ext" }

  $result.execution.attempted = $true
  $proc = $null
  switch ($ext) {
    '.exe' { $proc = Start-Process -FilePath $SamplePath -PassThru -WindowStyle Hidden }
    '.com' { $proc = Start-Process -FilePath $SamplePath -PassThru -WindowStyle Hidden }
    '.scr' { $proc = Start-Process -FilePath $SamplePath -PassThru -WindowStyle Hidden }
    '.bat' { $proc = Start-Process -FilePath 'cmd.exe' -ArgumentList @('/d','/c',"`"$SamplePath`"") -PassThru -WindowStyle Hidden }
    '.cmd' { $proc = Start-Process -FilePath 'cmd.exe' -ArgumentList @('/d','/c',"`"$SamplePath`"") -PassThru -WindowStyle Hidden }
    '.ps1' { $proc = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','RemoteSigned','-File',"`"$SamplePath`"") -PassThru -WindowStyle Hidden }
    '.vbs' { $proc = Start-Process -FilePath 'cscript.exe' -ArgumentList @('//Nologo',"`"$SamplePath`"") -PassThru -WindowStyle Hidden }
    '.js' { $proc = Start-Process -FilePath 'cscript.exe' -ArgumentList @('//Nologo',"`"$SamplePath`"") -PassThru -WindowStyle Hidden }
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
}

$result.finalProcesses = @(Get-ProcessSnapshot)
$result.recentFiles = @(Get-RecentFiles $started)
$result.finishedAt = (Get-Date).ToUniversalTime().ToString('o')

$parent = Split-Path -Parent $OutputPath
New-Item -ItemType Directory -Path $parent -Force | Out-Null
$result | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
