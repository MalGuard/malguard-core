param(
  [Parameter(Mandatory=$true)][ValidateSet('Protect','Restore','Status')][string]$Mode,
  [Parameter(Mandatory=$true)][string]$Target,
  [Parameter(Mandatory=$false)][string]$Backup
)

$ErrorActionPreference = 'Stop'
$targetFull = [IO.Path]::GetFullPath($Target)
if (-not (Test-Path -LiteralPath $targetFull -PathType Container)) { throw 'protected root must be an existing directory' }

function Emit($obj) { $obj | ConvertTo-Json -Compress -Depth 5; exit 0 }

if ($Mode -eq 'Status') {
  $acl = Get-Acl -LiteralPath $targetFull
  $sddl = $acl.Sddl
  $protected = $sddl -match 'D:P' -and $sddl -match ';;;SY\)' -and $sddl -match ';;;BA\)' -and $sddl -match ';;;BU\)'
  Emit ([ordered]@{ ok=$true; mode='Status'; target=$targetFull; protected=[bool]$protected; sddl=$sddl })
}

if (-not $Backup) { throw 'backup path required' }
$backupFull = [IO.Path]::GetFullPath($Backup)
$backupDir = Split-Path -Parent $backupFull
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

if ($Mode -eq 'Protect') {
  $current = Get-Acl -LiteralPath $targetFull
  if (-not (Test-Path -LiteralPath $backupFull -PathType Leaf)) {
    [IO.File]::WriteAllText($backupFull, $current.Sddl, [Text.UTF8Encoding]::new($false))
  }

  # Threat model: unprivileged/interactively running software cannot add, replace,
  # rename or delete protected mod files. SYSTEM (the MalGuard service) and local
  # Administrators retain full control. Built-in Users retain read/execute only.
  $sddl = 'O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)'
  $security = New-Object System.Security.AccessControl.DirectorySecurity
  $security.SetSecurityDescriptorSddlForm($sddl)
  Set-Acl -LiteralPath $targetFull -AclObject $security

  $verify = Get-Acl -LiteralPath $targetFull
  $verified = $verify.Sddl -match 'D:P' -and $verify.Sddl -match ';;;SY\)' -and $verify.Sddl -match ';;;BA\)' -and $verify.Sddl -match ';;;BU\)'
  if (-not $verified) { throw 'ACL verification failed after protection' }
  Emit ([ordered]@{ ok=$true; mode='Protect'; target=$targetFull; protected=$true; sddl=$verify.Sddl; backup=$backupFull })
}

if ($Mode -eq 'Restore') {
  if (-not (Test-Path -LiteralPath $backupFull -PathType Leaf)) { throw 'ACL backup missing' }
  $saved = [IO.File]::ReadAllText($backupFull, [Text.Encoding]::UTF8).Trim()
  if (-not $saved) { throw 'ACL backup empty' }
  $security = New-Object System.Security.AccessControl.DirectorySecurity
  $security.SetSecurityDescriptorSddlForm($saved)
  Set-Acl -LiteralPath $targetFull -AclObject $security
  $verify = Get-Acl -LiteralPath $targetFull
  if ($verify.Sddl -ne $saved) {
    # Windows may canonicalize semantically equivalent SDDL. Compare binary forms.
    $a = New-Object System.Security.AccessControl.DirectorySecurity
    $a.SetSecurityDescriptorSddlForm($saved)
    $b = New-Object System.Security.AccessControl.DirectorySecurity
    $b.SetSecurityDescriptorSddlForm($verify.Sddl)
    $ab = $a.GetSecurityDescriptorBinaryForm()
    $bb = $b.GetSecurityDescriptorBinaryForm()
    if ($ab.Length -ne $bb.Length -or (Compare-Object $ab $bb)) { throw 'ACL restore verification failed' }
  }
  Emit ([ordered]@{ ok=$true; mode='Restore'; target=$targetFull; protected=$false; sddl=$verify.Sddl })
}
