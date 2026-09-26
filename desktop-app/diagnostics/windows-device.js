'use strict';
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');

// Fixed queries: never enumerate accounts, serials, adapters, disks, or network identifiers.
const SCRIPT = "$ErrorActionPreference='Stop'; $s=Get-CimInstance Win32_ComputerSystem -Property Manufacturer,Model,TotalPhysicalMemory; $c=@(Get-CimInstance Win32_Processor -Property Name,NumberOfCores,NumberOfLogicalProcessors); $w=Get-CimInstance Win32_OperatingSystem -Property Caption,Version,BuildNumber; $g=@(Get-CimInstance Win32_VideoController -Property Name); @{deviceManufacturer=$s.Manufacturer;deviceModel=$s.Model;cpuModel=($c.Name -join ', ');cpuCores=($c|Measure-Object NumberOfCores -Sum).Sum;cpuThreads=($c|Measure-Object NumberOfLogicalProcessors -Sum).Sum;ramBytes=$s.TotalPhysicalMemory;gpuModel=($g.Name -join ', ');windowsEdition=$w.Caption;windowsVersion=$w.Version;windowsBuild=$w.BuildNumber}|ConvertTo-Json -Compress";
function text(value) { return typeof value === 'string' ? value.replace(/[\x00-\x1f\x7f]/g, '').slice(0, 160) : null; }
function number(value, max) { return Number.isSafeInteger(Number(value)) && Number(value) > 0 && Number(value) <= max ? Number(value) : null; }
async function collectWindowsDevice() {
  if (process.platform !== 'win32') return { architecture: process.arch };
  const exe = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const raw = await new Promise(resolve => execFile(exe, ['-NoLogo','-NoProfile','-NonInteractive','-Command', SCRIPT], { windowsHide: true, timeout: 4000, maxBuffer: 16384 }, (err, stdout) => {
    if (err) return resolve({});
    try { resolve(JSON.parse(stdout)); } catch (_) { resolve({}); }
  }));
  const result = { architecture: process.arch, ramBytes: number(raw.ramBytes || os.totalmem(), 2 ** 50) };
  for (const key of ['deviceManufacturer','deviceModel','cpuModel','gpuModel','windowsEdition','windowsVersion','windowsBuild']) result[key] = text(raw[key]);
  result.cpuCores = number(raw.cpuCores, 4096); result.cpuThreads = number(raw.cpuThreads, 8192);
  return result;
}
module.exports = { collectWindowsDevice, SCRIPT };
