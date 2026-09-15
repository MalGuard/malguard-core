param(
  [Parameter(Mandatory=$true)][string]$InputPath,
  [Parameter(Mandatory=$true)][string]$OutputPath,
  [Parameter(Mandatory=$true)][string]$SessionId
)

$ErrorActionPreference = 'Stop'
$result = [ordered]@{
  schemaVersion = '1.0.0'
  sessionId = $SessionId
  sandboxReached = $true
  inputReadOnly = $false
  outputWritable = $false
  networkDefaultRoutePresent = $null
  error = $null
}

try {
  if (-not (Test-Path -LiteralPath $InputPath -PathType Container)) { throw 'input mapping missing' }
  $probe = Join-Path $InputPath 'should-not-write.txt'
  try {
    Set-Content -LiteralPath $probe -Value 'blocked' -ErrorAction Stop
    $result.inputReadOnly = $false
    Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
  } catch {
    $result.inputReadOnly = $true
  }

  try {
    $routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)
    $result.networkDefaultRoutePresent = ($routes.Count -gt 0)
  } catch {
    $result.networkDefaultRoutePresent = $null
  }

  $parent = Split-Path -Parent $OutputPath
  New-Item -ItemType Directory -Path $parent -Force | Out-Null
  $result.outputWritable = $true
} catch {
  $result.error = $_.Exception.Message
}

$result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
Start-Sleep -Milliseconds 300
shutdown.exe /s /t 0 /f | Out-Null
