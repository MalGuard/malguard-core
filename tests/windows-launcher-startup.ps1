param([Parameter(Mandatory=$true)][string]$Launcher, [Parameter(Mandatory=$true)][string]$Node)

$ErrorActionPreference = 'Stop'
$fixture = Join-Path $env:RUNNER_TEMP ('malguard-launcher-startup-' + [guid]::NewGuid().ToString('N'))
$bin = Join-Path $fixture 'desktop-app\bin'
$runtime = Join-Path $fixture 'desktop-app\runtime'
$integrity = Join-Path $fixture 'desktop-app\integrity'
$logs = Join-Path $env:LOCALAPPDATA 'MalGuard\logs'

function Stop-FixtureProcesses {
  Get-CimInstance Win32_Process -Filter "Name = 'node.exe'" |
    Where-Object { $_.CommandLine -and $_.CommandLine.Contains($fixture) } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
  Start-Sleep -Milliseconds 250
}

function Invoke-Launcher([string]$script, [int]$expectedExit, [int]$minimumMs = 0) {
  Set-Content -LiteralPath (Join-Path $fixture 'desktop-app\server.js') -Value $script -Encoding utf8
  $watch = [Diagnostics.Stopwatch]::StartNew()
  $process = Start-Process -FilePath (Join-Path $bin 'MalGuard.exe') -ArgumentList '--headless-startup-test' -PassThru
  if (-not $process.WaitForExit(30000)) {
    Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
    throw 'Launcher did not exit within 30 seconds'
  }
  $watch.Stop()
  if ($process.ExitCode -ne $expectedExit) { throw "Launcher exited $($process.ExitCode); expected $expectedExit" }
  if ($watch.ElapsedMilliseconds -lt $minimumMs) { throw "Launcher reported readiness prematurely after $($watch.ElapsedMilliseconds) ms" }
  $log = Get-ChildItem -LiteralPath $logs -Filter "startup-$($process.Id)-*.log" -File | Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if (-not $log) { throw 'Launcher did not write a startup diagnostic log' }
  return Get-Content -LiteralPath $log.FullName -Raw
}

try {
  New-Item -ItemType Directory -Path $bin,$runtime,$integrity -Force | Out-Null
  Copy-Item -LiteralPath $Launcher -Destination (Join-Path $bin 'MalGuard.exe')
  Copy-Item -LiteralPath $Node -Destination (Join-Path $runtime 'node.exe')
  Set-Content -LiteralPath (Join-Path $fixture 'PACKAGE-MANIFEST.json') -Value '{}' -Encoding utf8
  Set-Content -LiteralPath (Join-Path $fixture 'SHA256SUMS.txt') -Value 'fixture' -Encoding utf8
  Set-Content -LiteralPath (Join-Path $integrity 'preload.js') -Value '// Isolated launcher fixture; package integrity is verified separately.' -Encoding utf8
  # Match server.js json(): JSON.stringify(body, null, 2). A compact fixture hid a real launcher failure.
  $server = "const http=require('http');setTimeout(()=>http.createServer((req,res)=>{res.setHeader('Content-Type','application/json');res.end(JSON.stringify({ok:true,product:'MalGuard Desktop'},null,2))}).listen(18777,'127.0.0.1'),DELAY);"

  try {
    Invoke-Launcher ($server.Replace('DELAY','0')) 0 | Out-Null
    Write-Host 'Launcher successful /api/status startup PASS'
  } finally { Stop-FixtureProcesses }

  try {
    Invoke-Launcher ($server.Replace('DELAY','2300')) 0 2000 | Out-Null
    Write-Host 'Launcher delayed startup readiness PASS'
  } finally { Stop-FixtureProcesses }

  $result = Invoke-Launcher "throw new Error('fixture-immediate-crash')" 6
  if ($result -notmatch 'fixture-immediate-crash') { throw 'Immediate Node crash was not captured in diagnostic' }
  Write-Host 'Launcher immediate Node crash diagnostic PASS'

  $occupied = Join-Path $fixture 'occupied.js'
  Set-Content -LiteralPath $occupied -Value "require('http').createServer((req,res)=>res.end('other service')).listen(18777,'127.0.0.1')" -Encoding utf8
  try {
    $holder = Start-Process -FilePath (Join-Path $runtime 'node.exe') -ArgumentList ('"' + $occupied + '"') -PassThru -WindowStyle Hidden
    $ready = $false
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
      try { if ((Invoke-WebRequest -Uri 'http://127.0.0.1:18777/api/status' -TimeoutSec 1).StatusCode -eq 200) { $ready = $true; break } } catch {}
      Start-Sleep -Milliseconds 100
    }
    if (-not $ready) { throw 'Port conflict fixture could not bind port 18777' }
    $result = Invoke-Launcher ($server.Replace('DELAY','0')) 6
    if ($result -notmatch 'EADDRINUSE') { throw 'Port conflict was not recorded in startup diagnostic' }
    Write-Host 'Launcher occupied port diagnostic PASS'
  } finally { Stop-FixtureProcesses }

  Remove-Item -LiteralPath (Join-Path $fixture 'desktop-app\server.js') -Force
  $process = Start-Process -FilePath (Join-Path $bin 'MalGuard.exe') -ArgumentList '--headless-startup-test' -PassThru
  if (-not $process.WaitForExit(30000)) { throw 'Incomplete install launcher did not exit' }
  if ($process.ExitCode -ne 2) { throw "Incomplete install returned $($process.ExitCode), expected 2" }
  Write-Host 'Launcher incomplete install rejection PASS'
} finally {
  Stop-FixtureProcesses
  Remove-Item -LiteralPath $fixture -Recurse -Force -ErrorAction SilentlyContinue
}
