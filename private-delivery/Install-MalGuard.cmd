@echo off
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Activate-MalGuard.ps1"
set MG_INSTALL_EXIT=%errorlevel%
if not "%MG_INSTALL_EXIT%"=="0" pause
exit /b %MG_INSTALL_EXIT%
