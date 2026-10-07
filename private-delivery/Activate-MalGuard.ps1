param([switch]$Quiet)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2
try {
  $env:PSModulePath=Join-Path $PSHOME 'Modules'
  foreach ($module in @('Microsoft.PowerShell.Management','Microsoft.PowerShell.Utility','Microsoft.PowerShell.Security')) {
    Import-Module -Name (Join-Path $PSHOME ('Modules\'+$module+'\'+$module+'.psd1')) -ErrorAction Stop
  }
  $setup=Join-Path $PSScriptRoot 'MalGuard-Online-Setup-x64.exe'
  $licenseFile=Join-Path $PSScriptRoot 'device-license.json'
  $manifestFile=Join-Path $PSScriptRoot 'private-release.json'
  foreach ($path in @($setup,$licenseFile,$manifestFile)) {
    $item=Get-Item -LiteralPath $path -Force
    if ($item -isnot [IO.FileInfo] -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {throw 'A required delivery file is missing or is a symbolic link.'}
  }
  if ((Get-Item -LiteralPath $licenseFile).Length -gt 4096 -or (Get-Item -LiteralPath $manifestFile).Length -gt 8192) {throw 'Delivery metadata is oversized.'}
  $license=Get-Content -LiteralPath $licenseFile -Raw | ConvertFrom-Json
  $manifest=Get-Content -LiteralPath $manifestFile -Raw | ConvertFrom-Json
  if ($manifest.schema -ne 1 -or $manifest.app_version -ne '1.3.0' -or $manifest.engine_version -ne '1.2.0' -or
      $manifest.filename -ne 'MalGuard-Online-Setup-x64.exe' -or $manifest.sha256 -notmatch '^[a-f0-9]{64}$' -or
      $manifest.requires_device_license -ne $true) {throw 'This is not the expected private MalGuard release.'}
  if ((Get-FileHash -LiteralPath $setup -Algorithm SHA256).Hash.ToLowerInvariant() -ne $manifest.sha256) {throw 'Installer checksum mismatch. Obtain the original private archive again.'}
  if ($license.schema -ne 1 -or $license.product -ne 'MalGuard' -or $license.app_version -ne '1.3.0' -or $license.fingerprint -notmatch '^[a-f0-9]{64}$') {throw 'Device license metadata is invalid.'}
  $registry=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
  try {
    $key=$registry.OpenSubKey('SOFTWARE\Microsoft\Cryptography')
    try {$guid=[string]$key.GetValue('MachineGuid')} finally {$key.Dispose()}
  } finally {$registry.Dispose()}
  $hash=[Security.Cryptography.SHA256]::Create()
  try {$fingerprint=([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($guid.Trim().ToLowerInvariant())))).Replace('-','').ToLowerInvariant()} finally {$hash.Dispose()}
  if ($fingerprint -cne $license.fingerprint) {throw 'This private license belongs to another Windows device. Nothing has been installed.'}
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
  $principal=New-Object Security.Principal.WindowsPrincipal($identity)
  if (-not [Environment]::Is64BitProcess -or -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $powershell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {$powershell=Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'}
    $arguments='-NoLogo -NoProfile -ExecutionPolicy Bypass -File "'+$PSCommandPath+'"'
    if ($Quiet) {$arguments+=' -Quiet'}
    $process=Start-Process -FilePath $powershell -ArgumentList $arguments -Verb RunAs -PassThru
    if (-not $process.WaitForExit(660000)) {throw 'Activation exceeded its deadline.'}
    exit $process.ExitCode
  }
  $common=[Environment]::GetFolderPath('CommonApplicationData')
  $product=Join-Path $common 'MalGuard'
  $folder=Join-Path $product 'Licenses'
  foreach ($path in @($common,$product,$folder)) {
    if (Test-Path -LiteralPath $path) {
      $item=Get-Item -LiteralPath $path -Force
      if ($item -isnot [IO.DirectoryInfo] -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {throw 'The system license directory is not an ordinary directory.'}
    }
  }
  New-Item -ItemType Directory -Path $folder -Force | Out-Null
  $acl=New-Object Security.AccessControl.DirectorySecurity
  $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)')
  (Get-Item -LiteralPath $folder).SetAccessControl($acl)
  $destination=Join-Path $folder 'desktop-1.3.0.json'
  if (Test-Path -LiteralPath $destination) {
    $item=Get-Item -LiteralPath $destination -Force
    if ($item -isnot [IO.FileInfo] -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {throw 'The existing license is not an ordinary file.'}
  }
  $temporary=Join-Path $folder ([guid]::NewGuid().ToString('N')+'.tmp')
  $stream=[IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try {$bytes=[IO.File]::ReadAllBytes($licenseFile);$stream.Write($bytes,0,$bytes.Length);$stream.Flush()} finally {$stream.Dispose()}
  try {
    if (Test-Path -LiteralPath $destination) {[IO.File]::Replace($temporary,$destination,$null)}
    else {[IO.File]::Move($temporary,$destination)}
  } finally {if (Test-Path -LiteralPath $temporary) {Remove-Item -LiteralPath $temporary -Force}}
  $fileAcl=New-Object Security.AccessControl.FileSecurity
  $fileAcl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)')
  (Get-Item -LiteralPath $destination).SetAccessControl($fileAcl)
  # The frozen engine independently verifies the signature and device before
  # setup changes the working installation. Copying a JSON file grants nothing.
  if ($Quiet) {$env:MALGUARD_SETUP_QUIET='1'}
  $process=Start-Process -FilePath $setup -WorkingDirectory $PSScriptRoot -PassThru
  if (-not $process.WaitForExit(600000)) {throw 'Installer exceeded its deadline.'}
  if ($process.ExitCode -ne 0) {throw ('Installer exited with code '+$process.ExitCode)}
  exit 0
} catch {
  Write-Error $_.Exception.Message -ErrorAction Continue
  if (-not $Quiet) {
    Add-Type -AssemblyName System.Windows.Forms
    [Windows.Forms.MessageBox]::Show($_.Exception.Message,'MalGuard private installation') | Out-Null
  }
  exit 42
}
