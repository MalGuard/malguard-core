param(
  [Parameter(Mandatory=$true)][string]$Path,
  [string]$ExpectedThumbprint = $env:MALGUARD_WINDOWS_SIGNER_THUMBPRINT
)

$ErrorActionPreference = 'Stop'

function Fail([string]$Message) {
  throw "WINDOWS_RELEASE_SIGNATURE_FAILED: $Message"
}

if ([string]::IsNullOrWhiteSpace($ExpectedThumbprint)) {
  Fail 'MALGUARD_WINDOWS_SIGNER_THUMBPRINT is required for a public Windows release.'
}

$expected = ($ExpectedThumbprint -replace '[^A-Fa-f0-9]', '').ToUpperInvariant()
if ($expected.Length -lt 40) {
  Fail 'expected publisher certificate thumbprint is invalid.'
}

$root = Resolve-Path -LiteralPath $Path -ErrorAction Stop
$items = @()
if ((Get-Item -LiteralPath $root).PSIsContainer) {
  $items = @(Get-ChildItem -LiteralPath $root -File -Recurse | Where-Object { $_.Extension -in @('.exe', '.dll') })
} else {
  $item = Get-Item -LiteralPath $root
  if ($item.Extension -notin @('.exe', '.dll')) { Fail 'target is not a Windows executable or DLL.' }
  $items = @($item)
}

if ($items.Count -eq 0) { Fail 'no Windows executable files were found to verify.' }

foreach ($item in $items) {
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    Fail "reparse-point executable is forbidden: $($item.FullName)"
  }

  $signature = Get-AuthenticodeSignature -LiteralPath $item.FullName
  if ($signature.Status -ne 'Valid') {
    Fail "invalid or missing Authenticode signature: $($item.FullName) ($($signature.Status))"
  }
  if (-not $signature.SignerCertificate) {
    Fail "signer certificate missing: $($item.FullName)"
  }
  $actual = ($signature.SignerCertificate.Thumbprint -replace '[^A-Fa-f0-9]', '').ToUpperInvariant()
  if ($actual -ne $expected) {
    Fail "unexpected signer certificate for $($item.FullName)"
  }
}

Write-Host "Authenticode PASS: $($items.Count) Windows executable file(s) signed by the pinned MalGuard publisher certificate."
exit 0
