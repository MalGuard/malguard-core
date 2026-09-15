param(
  [Parameter(Mandatory=$true)][ValidateSet('Snapshot','Terminate')][string]$Mode,
  [Parameter(Mandatory=$false)][int]$Pid = 0,
  [Parameter(Mandatory=$false)][string]$ExpectedPath = ''
)

$ErrorActionPreference = 'Stop'

function Emit($obj) {
  $obj | ConvertTo-Json -Compress -Depth 8
  exit 0
}

function Get-ConfiguredRoots {
  $encoded = [Environment]::GetEnvironmentVariable('MALGUARD_RUNTIME_ROOTS_B64')
  if ([string]::IsNullOrWhiteSpace($encoded)) { throw 'runtime roots are missing' }
  $json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded))
  $roots = ConvertFrom-Json -InputObject $json
  if ($null -eq $roots) { throw 'runtime roots are invalid' }
  return @($roots | ForEach-Object { [IO.Path]::GetFullPath([string]$_) })
}

function Test-WithinRoot([string]$Candidate, [string[]]$Roots) {
  if ([string]::IsNullOrWhiteSpace($Candidate)) { return $false }
  $full = [IO.Path]::GetFullPath($Candidate).TrimEnd('\')
  foreach ($root in $Roots) {
    $r = [IO.Path]::GetFullPath($root).TrimEnd('\')
    if ($full.Equals($r, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    if ($full.StartsWith($r + '\', [StringComparison]::OrdinalIgnoreCase)) { return $true }
  }
  return $false
}

$roots = Get-ConfiguredRoots

if ($Mode -eq 'Terminate') {
  if ($Pid -le 0 -or [string]::IsNullOrWhiteSpace($ExpectedPath)) { throw 'pid and expected path are required' }
  $expected = [IO.Path]::GetFullPath($ExpectedPath)
  if (-not (Test-WithinRoot $expected $roots)) { throw 'expected process path is outside protected roots' }
  $p = Get-Process -Id $Pid -ErrorAction Stop
  $actual = [IO.Path]::GetFullPath([string]$p.Path)
  if (-not $actual.Equals($expected, [StringComparison]::OrdinalIgnoreCase)) { throw 'process identity changed before termination' }
  Stop-Process -Id $Pid -Force -ErrorAction Stop
  Emit ([ordered]@{ ok=$true; mode='Terminate'; pid=$Pid; path=$actual; terminated=$true })
}

$processes = New-Object System.Collections.Generic.List[object]
$truncated = $false
foreach ($p in (Get-Process | Sort-Object Id)) {
  if ($processes.Count -ge 128) { $truncated = $true; break }
  try { $processPath = [string]$p.Path } catch { continue }
  if ([string]::IsNullOrWhiteSpace($processPath)) { continue }
  if (-not (Test-WithinRoot $processPath $roots)) { continue }

  $modules = New-Object System.Collections.Generic.List[string]
  $moduleEnumerationOk = $true
  try {
    foreach ($m in $p.Modules) {
      if ($modules.Count -ge 512) { $truncated = $true; break }
      try {
        $fileName = [string]$m.FileName
        if (-not [string]::IsNullOrWhiteSpace($fileName)) { [void]$modules.Add([IO.Path]::GetFullPath($fileName)) }
      } catch { }
    }
  } catch {
    $moduleEnumerationOk = $false
  }

  [void]$processes.Add([ordered]@{
    pid = [int]$p.Id
    name = [string]$p.ProcessName
    path = [IO.Path]::GetFullPath($processPath)
    moduleEnumerationOk = [bool]$moduleEnumerationOk
    modules = @($modules)
  })
}

Emit ([ordered]@{ ok=$true; mode='Snapshot'; roots=$roots; processes=@($processes); truncated=[bool]$truncated })
