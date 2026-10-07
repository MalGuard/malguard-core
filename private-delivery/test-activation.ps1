param([Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference='Stop'
$env:PSModulePath=Join-Path $PSHOME 'Modules'
$root=Join-Path $env:RUNNER_TEMP ('malguard-activation-qa-'+[guid]::NewGuid().ToString('N'))
$system=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'MalGuard/Licenses'
if (Test-Path -LiteralPath $system) {throw 'An existing license directory must not be modified by fixtures'}
New-Item -ItemType Directory -Path $root | Out-Null
$marker=Join-Path $root 'trusted-stub-launched.txt'
$env:MALGUARD_ACTIVATION_TEST_MARKER=$marker
$checks=@()
try {
  Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Activate-MalGuard.ps1') -Destination $root
  $setup=Join-Path $root 'MalGuard-Online-Setup-x64.exe'
  # Compile an explicitly trusted inert fixture. It is not the shipped engine
  # or installer and no sample under analysis is executed.
  Add-Type -TypeDefinition 'using System; using System.IO; public class InertActivationFixture { public static void Main() { File.WriteAllText(Environment.GetEnvironmentVariable("MALGUARD_ACTIVATION_TEST_MARKER"), "Trusted activation fixture only; not the production installer."); } }' -OutputAssembly $setup -OutputType ConsoleApplication
  $manifest=@{schema=1;app_version='1.3.0';engine_version='1.2.0';filename='MalGuard-Online-Setup-x64.exe';sha256=(Get-FileHash $setup -Algorithm SHA256).Hash.ToLowerInvariant();requires_device_license=$true}
  $manifest | ConvertTo-Json | Set-Content (Join-Path $root 'private-release.json') -Encoding UTF8
  $license=@{schema=1;product='MalGuard';app_version='1.3.0';fingerprint=('0'*64);signature='Activation file writer fixture; genuine engine independently verifies signatures.'}
  $file=Join-Path $root 'device-license.json'
  $license | ConvertTo-Json | Set-Content $file -Encoding UTF8
  $powershell=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
  $arguments='-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $root 'Activate-MalGuard.ps1')+'" -Quiet'
  $process=Start-Process -FilePath $powershell -ArgumentList $arguments -PassThru -Wait
  if ($process.ExitCode -ne 42 -or (Test-Path $marker) -or (Test-Path $system)) {throw 'Wrong device was not rejected before writes or execution'}
  $checks+=@{name='wrong-device-rejected-before-license-write-or-setup';passed=$true}
  $registry=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
  try {$key=$registry.OpenSubKey('SOFTWARE\Microsoft\Cryptography');try {$guid=[string]$key.GetValue('MachineGuid')} finally {$key.Dispose()}} finally {$registry.Dispose()}
  $hash=[Security.Cryptography.SHA256]::Create()
  try {$license.fingerprint=([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($guid.Trim().ToLowerInvariant())))).Replace('-','').ToLowerInvariant()} finally {$hash.Dispose()}
  $license | ConvertTo-Json | Set-Content $file -Encoding UTF8
  $expected=$manifest.sha256
  $manifest.sha256='0'*64
  $manifest | ConvertTo-Json | Set-Content (Join-Path $root 'private-release.json') -Encoding UTF8
  $process=Start-Process -FilePath $powershell -ArgumentList $arguments -PassThru -Wait
  if ($process.ExitCode -ne 42 -or (Test-Path $marker) -or (Test-Path $system)) {throw 'Modified installer was not rejected before writes or execution'}
  $checks+=@{name='installer-hash-mismatch-rejected';passed=$true}
  $manifest.sha256=$expected
  $manifest | ConvertTo-Json | Set-Content (Join-Path $root 'private-release.json') -Encoding UTF8
  $process=Start-Process -FilePath $powershell -ArgumentList $arguments -PassThru -Wait
  if ($process.ExitCode -ne 0 -or -not (Test-Path $marker)) {throw 'Same-device activation file writer failed'}
  $checks+=@{name='same-device-starts-trusted-stub';passed=$true}
  $destination=Join-Path $system 'desktop-1.3.0.json'
  if ((Get-FileHash $file).Hash -ne (Get-FileHash $destination).Hash) {throw 'License bytes changed during placement'}
  foreach ($path in @($system,$destination)) {
    $acl=Get-Acl -LiteralPath $path
    if (-not $acl.AreAccessRulesProtected -or $acl.Owner -notmatch 'Administrators$|SYSTEM$') {throw 'License ACL owner/inheritance failed'}
    foreach ($ace in $acl.Access) {
      if ($ace.IdentityReference -match 'Users$' -and ($ace.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Write) -ne 0) {throw 'Users can modify the license directory/file'}
    }
  }
  $checks+=@{name='license-bytes-and-system-acls';passed=$true}
  $process=Start-Process -FilePath $powershell -ArgumentList $arguments -PassThru -Wait
  if ($process.ExitCode -ne 0) {throw 'License replacement was not idempotent'}
  $checks+=@{name='same-device-repeated-activation';passed=$true}
} catch {
  @{passed=$checks.Count;failed=1;error=$_.Exception.Message;position=$_.InvocationInfo.PositionMessage;trusted_stub_only=$true} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $Output -Encoding UTF8
  throw
} finally {
  if (Test-Path -LiteralPath $system) {Remove-Item -LiteralPath $system -Recurse -Force}
  Remove-Item -LiteralPath $root -Recurse -Force
  Remove-Item Env:MALGUARD_ACTIVATION_TEST_MARKER -ErrorAction SilentlyContinue
}
@{passed=$checks.Count;failed=0;checks=$checks;trusted_stub_only=$true;production_installation_tested=$false} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $Output -Encoding UTF8
exit 0
