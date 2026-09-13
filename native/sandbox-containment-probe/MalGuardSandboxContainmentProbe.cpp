#include <windows.h>
#include <algorithm>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

static constexpr const char* kSchema = "1.0.0";
static constexpr DWORD kProductionCpuRate = 2000; // 20% of system CPU capacity.
static constexpr SIZE_T kProductionMemoryLimit = 64ull * 1024ull * 1024ull;
static constexpr DWORD kMemoryLimitedExit = 42;
static constexpr DWORD kMemoryUnexpectedSuccessExit = 43;

struct ChildProcess {
  HANDLE process = nullptr;
  HANDLE thread = nullptr;
};

static void CloseChild(ChildProcess& child) {
  if (child.thread) CloseHandle(child.thread);
  if (child.process) CloseHandle(child.process);
  child.thread = nullptr;
  child.process = nullptr;
}

static bool SetExtendedLimits(HANDLE job, SIZE_T memoryLimit, DWORD activeProcessLimit) {
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION ext{};
  ext.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  if (memoryLimit > 0) {
    ext.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    ext.ProcessMemoryLimit = memoryLimit;
  }
  if (activeProcessLimit > 0) {
    ext.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    ext.BasicLimitInformation.ActiveProcessLimit = activeProcessLimit;
  }
  return SetInformationJobObject(job, JobObjectExtendedLimitInformation, &ext, sizeof(ext)) == TRUE;
}

static bool SetCpuHardCap(HANDLE job, DWORD cpuRate) {
  JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpu{};
  cpu.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
  cpu.CpuRate = cpuRate;
  return SetInformationJobObject(job, JobObjectCpuRateControlInformation, &cpu, sizeof(cpu)) == TRUE;
}

static bool SetJobLimits(HANDLE job) {
  return SetExtendedLimits(job, kProductionMemoryLimit, 1) && SetCpuHardCap(job, kProductionCpuRate);
}

static int ChildBusyLoopLong() {
  volatile unsigned long long value = 0;
  const ULONGLONG deadline = GetTickCount64() + 15000;
  while (GetTickCount64() < deadline) {
    value = (value * 1664525ull) + 1013904223ull;
  }
  return static_cast<int>(value & 0x7f);
}

static int ChildMemory96MiB() {
  constexpr SIZE_T kChunk = 4ull * 1024ull * 1024ull;
  constexpr SIZE_T kTarget = 96ull * 1024ull * 1024ull;
  std::vector<void*> allocations;
  SIZE_T committed = 0;

  while (committed < kTarget) {
    void* block = VirtualAlloc(nullptr, kChunk, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!block) {
      for (void* value : allocations) VirtualFree(value, 0, MEM_RELEASE);
      return kMemoryLimitedExit;
    }
    volatile unsigned char* bytes = static_cast<volatile unsigned char*>(block);
    for (SIZE_T offset = 0; offset < kChunk; offset += 4096) bytes[offset] = 0x4d;
    allocations.push_back(block);
    committed += kChunk;
  }

  Sleep(250);
  for (void* value : allocations) VirtualFree(value, 0, MEM_RELEASE);
  return kMemoryUnexpectedSuccessExit;
}

static int ChildSleepLong() {
  Sleep(15000);
  return 0;
}

static std::wstring Quote(const std::wstring& value) {
  return L"\"" + value + L"\"";
}

static bool CreateSelfChild(const std::wstring& exePath, const wchar_t* mode, ChildProcess& child) {
  std::wstring command = Quote(exePath) + L" " + mode;
  STARTUPINFOW si{};
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi{};
  const DWORD flags = CREATE_SUSPENDED | CREATE_NO_WINDOW;
  const BOOL created = CreateProcessW(
      exePath.c_str(),
      command.data(),
      nullptr,
      nullptr,
      FALSE,
      flags,
      nullptr,
      nullptr,
      &si,
      &pi);
  if (!created) return false;
  child.process = pi.hProcess;
  child.thread = pi.hThread;
  return true;
}

static bool ResumeChild(ChildProcess& child) {
  return child.thread && ResumeThread(child.thread) != static_cast<DWORD>(-1);
}

static double FileTimeToMilliseconds(const FILETIME& value) {
  ULARGE_INTEGER v{};
  v.LowPart = value.dwLowDateTime;
  v.HighPart = value.dwHighDateTime;
  return static_cast<double>(v.QuadPart) / 10000.0;
}

static bool ReadProcessCpuMilliseconds(HANDLE process, double& cpuMs) {
  FILETIME created{}, exited{}, kernel{}, user{};
  if (!GetProcessTimes(process, &created, &exited, &kernel, &user)) return false;
  cpuMs = FileTimeToMilliseconds(kernel) + FileTimeToMilliseconds(user);
  return true;
}

static bool WaitForExitCode(HANDLE process, DWORD timeoutMs, DWORD& exitCode) {
  const DWORD wait = WaitForSingleObject(process, timeoutMs);
  if (wait != WAIT_OBJECT_0) return false;
  return GetExitCodeProcess(process, &exitCode) == TRUE;
}

struct CpuResult {
  bool tested = false;
  bool passed = false;
  double baselineRatio = 0.0;
  double cappedRatio = 0.0;
  DWORD testCpuRate = 0;
};

static bool MeasureBusyRatio(const std::wstring& exePath, HANDLE job, DWORD sampleMs, double& ratio) {
  ChildProcess child;
  if (!CreateSelfChild(exePath, L"--child-busy-long", child)) return false;
  bool assigned = true;
  if (job) assigned = AssignProcessToJobObject(job, child.process) == TRUE;
  if (!assigned || !ResumeChild(child)) {
    TerminateProcess(child.process, 0x4d47);
    CloseChild(child);
    return false;
  }

  const ULONGLONG started = GetTickCount64();
  Sleep(sampleMs);
  const ULONGLONG elapsed = std::max<ULONGLONG>(1, GetTickCount64() - started);
  double cpuMs = 0.0;
  const bool measured = ReadProcessCpuMilliseconds(child.process, cpuMs);
  if (job) TerminateJobObject(job, 0x4d47);
  else TerminateProcess(child.process, 0x4d47);
  WaitForSingleObject(child.process, 3000);
  CloseChild(child);
  if (!measured) return false;
  ratio = cpuMs / static_cast<double>(elapsed);
  return true;
}

static CpuResult TestCpuEnforcement(const std::wstring& exePath) {
  CpuResult result;
  result.tested = true;

  if (!MeasureBusyRatio(exePath, nullptr, 2500, result.baselineRatio)) return result;

  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  if (!job) return result;
  const DWORD processors = std::max<DWORD>(1, GetActiveProcessorCount(ALL_PROCESSOR_GROUPS));
  // Use a synthetic cap equivalent to about 20% of one logical processor so a
  // single busy thread is measurably throttled even on multi-core CI runners.
  result.testCpuRate = std::max<DWORD>(1, 2000u / processors);
  const bool configured = SetExtendedLimits(job, 256ull * 1024ull * 1024ull, 1) && SetCpuHardCap(job, result.testCpuRate);
  const bool measured = configured && MeasureBusyRatio(exePath, job, 3500, result.cappedRatio);
  CloseHandle(job);
  if (!measured) return result;

  const bool baselineWasBusy = result.baselineRatio >= 0.45;
  const bool cappedIsLow = result.cappedRatio <= 0.40;
  const bool materiallyReduced = result.cappedRatio <= (result.baselineRatio * 0.70);
  result.passed = baselineWasBusy && cappedIsLow && materiallyReduced;
  return result;
}

struct MemoryResult {
  bool tested = false;
  bool passed = false;
  DWORD baselineExitCode = STILL_ACTIVE;
  DWORD limitedExitCode = STILL_ACTIVE;
};

static MemoryResult TestMemoryEnforcement(const std::wstring& exePath) {
  MemoryResult result;
  result.tested = true;

  ChildProcess baseline;
  if (!CreateSelfChild(exePath, L"--child-memory-96", baseline) || !ResumeChild(baseline)) {
    if (baseline.process) TerminateProcess(baseline.process, 0x4d47);
    CloseChild(baseline);
    return result;
  }
  const bool baselineExited = WaitForExitCode(baseline.process, 10000, result.baselineExitCode);
  if (!baselineExited) TerminateProcess(baseline.process, 0x4d47);
  CloseChild(baseline);
  if (!baselineExited || result.baselineExitCode != kMemoryUnexpectedSuccessExit) return result;

  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  if (!job) return result;
  const bool configured = SetExtendedLimits(job, kProductionMemoryLimit, 1);
  ChildProcess limited;
  const bool created = configured && CreateSelfChild(exePath, L"--child-memory-96", limited);
  const bool assigned = created && AssignProcessToJobObject(job, limited.process) == TRUE;
  const bool resumed = assigned && ResumeChild(limited);
  const bool limitedExited = resumed && WaitForExitCode(limited.process, 10000, result.limitedExitCode);
  if (!limitedExited && limited.process) TerminateJobObject(job, 0x4d47);
  CloseChild(limited);
  CloseHandle(job);

  result.passed = limitedExited && result.limitedExitCode == kMemoryLimitedExit;
  return result;
}

struct ActiveProcessResult {
  bool tested = false;
  bool passed = false;
  bool configured = false;
  bool secondAssigned = false;
  DWORD secondAssignError = ERROR_SUCCESS;
  DWORD secondExitCode = STILL_ACTIVE;
};

static ActiveProcessResult TestActiveProcessLimit(const std::wstring& exePath) {
  ActiveProcessResult result;
  result.tested = true;

  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  if (!job) return result;
  result.configured = SetExtendedLimits(job, 256ull * 1024ull * 1024ull, 1);
  if (!result.configured) {
    CloseHandle(job);
    return result;
  }

  ChildProcess first;
  ChildProcess second;
  const bool firstCreated = CreateSelfChild(exePath, L"--child-sleep-long", first);
  const bool firstAssigned = firstCreated && AssignProcessToJobObject(job, first.process) == TRUE;
  const bool firstResumed = firstAssigned && ResumeChild(first);

  bool firstAlive = false;
  if (firstResumed) {
    DWORD firstExit = 0;
    firstAlive = GetExitCodeProcess(first.process, &firstExit) == TRUE && firstExit == STILL_ACTIVE;
  }

  const bool secondCreated = firstAlive && CreateSelfChild(exePath, L"--child-sleep-long", second);
  BOOL secondAssigned = FALSE;
  bool secondRejectedOrTerminated = false;
  if (secondCreated) {
    SetLastError(ERROR_SUCCESS);
    secondAssigned = AssignProcessToJobObject(job, second.process);
    result.secondAssigned = secondAssigned == TRUE;
    result.secondAssignError = secondAssigned ? ERROR_SUCCESS : GetLastError();
    if (!secondAssigned) {
      secondRejectedOrTerminated = true;
    } else {
      // Windows may accept the association and immediately terminate the new
      // process when JOB_OBJECT_LIMIT_ACTIVE_PROCESS is exceeded. Give that
      // asynchronous termination a short bounded window before evaluating it.
      const DWORD secondWait = WaitForSingleObject(second.process, 1000);
      if (secondWait == WAIT_OBJECT_0 && GetExitCodeProcess(second.process, &result.secondExitCode) == TRUE &&
          result.secondExitCode != STILL_ACTIVE) {
        secondRejectedOrTerminated = true;
      }
    }
  }

  if (second.process && !secondAssigned) {
    TerminateProcess(second.process, 0x4d47);
    WaitForSingleObject(second.process, 3000);
  }
  if (first.process) {
    TerminateJobObject(job, 0x4d47);
    WaitForSingleObject(first.process, 3000);
  }
  CloseChild(second);
  CloseChild(first);
  CloseHandle(job);

  result.passed = firstCreated && firstAssigned && firstResumed && firstAlive && secondCreated && secondRejectedOrTerminated;
  return result;
}

struct BaseContainmentResult {
  bool jobCreated = false;
  bool limitsConfigured = false;
  bool created = false;
  bool assigned = false;
  bool resumed = false;
  bool terminated = false;
};

static BaseContainmentResult TestBaseContainment(const std::wstring& exePath) {
  BaseContainmentResult result;
  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  if (!job) return result;
  result.jobCreated = true;
  result.limitsConfigured = SetJobLimits(job);
  if (!result.limitsConfigured) {
    CloseHandle(job);
    return result;
  }

  ChildProcess child;
  result.created = CreateSelfChild(exePath, L"--child-busy-long", child);
  if (result.created) {
    result.assigned = AssignProcessToJobObject(job, child.process) == TRUE;
    if (result.assigned) result.resumed = ResumeChild(child);
    Sleep(500);
    TerminateJobObject(job, 0x4d47);
    result.terminated = WaitForSingleObject(child.process, 3000) == WAIT_OBJECT_0;
  }
  CloseChild(child);
  CloseHandle(job);
  return result;
}

static int SelfTest() {
  wchar_t exePathBuffer[MAX_PATH]{};
  const DWORD n = GetModuleFileNameW(nullptr, exePathBuffer, MAX_PATH);
  if (n == 0 || n >= MAX_PATH) return 10;
  const std::wstring exePath(exePathBuffer, n);

  const BaseContainmentResult base = TestBaseContainment(exePath);
  const CpuResult cpu = TestCpuEnforcement(exePath);
  const MemoryResult memory = TestMemoryEnforcement(exePath);
  const ActiveProcessResult active = TestActiveProcessLimit(exePath);

  const bool ok = base.jobCreated && base.limitsConfigured && base.created && base.assigned && base.resumed && base.terminated &&
      cpu.tested && cpu.passed && memory.tested && memory.passed && active.tested && active.passed;

  std::ostringstream out;
  out << std::fixed << std::setprecision(3)
      << "{"
      << "\"schemaVersion\":\"" << kSchema << "\","
      << "\"ok\":" << (ok ? "true" : "false") << ","
      << "\"jobObjectCreated\":" << (base.jobCreated ? "true" : "false") << ","
      << "\"cpuHardCapConfigured\":" << (base.limitsConfigured ? "true" : "false") << ","
      << "\"cpuEnforcementTested\":" << (cpu.tested ? "true" : "false") << ","
      << "\"cpuEnforcementPassed\":" << (cpu.passed ? "true" : "false") << ","
      << "\"cpuBaselineBusyRatio\":" << cpu.baselineRatio << ","
      << "\"cpuCappedBusyRatio\":" << cpu.cappedRatio << ","
      << "\"cpuSyntheticTestRate\":" << cpu.testCpuRate << ","
      << "\"memoryLimitConfigured\":" << (base.limitsConfigured ? "true" : "false") << ","
      << "\"memoryEnforcementTested\":" << (memory.tested ? "true" : "false") << ","
      << "\"memoryEnforcementPassed\":" << (memory.passed ? "true" : "false") << ","
      << "\"memoryBaselineExitCode\":" << memory.baselineExitCode << ","
      << "\"memoryLimitedExitCode\":" << memory.limitedExitCode << ","
      << "\"activeProcessLimitConfigured\":" << (active.configured ? "true" : "false") << ","
      << "\"activeProcessLimitTested\":" << (active.tested ? "true" : "false") << ","
      << "\"activeProcessLimitPassed\":" << (active.passed ? "true" : "false") << ","
      << "\"activeProcessSecondAssigned\":" << (active.secondAssigned ? "true" : "false") << ","
      << "\"activeProcessSecondAssignError\":" << active.secondAssignError << ","
      << "\"activeProcessSecondExitCode\":" << active.secondExitCode << ","
      << "\"killOnCloseConfigured\":" << (base.limitsConfigured ? "true" : "false") << ","
      << "\"processCreatedSuspended\":" << (base.created ? "true" : "false") << ","
      << "\"assignedBeforeResume\":" << (base.assigned ? "true" : "false") << ","
      << "\"childResumed\":" << (base.resumed ? "true" : "false") << ","
      << "\"childTerminated\":" << (base.terminated ? "true" : "false")
      << "}";
  std::cout << out.str() << std::endl;
  return ok ? 0 : 20;
}

int wmain(int argc, wchar_t** argv) {
  if (argc == 2 && std::wstring(argv[1]) == L"--child-busy-long") return ChildBusyLoopLong();
  if (argc == 2 && std::wstring(argv[1]) == L"--child-memory-96") return ChildMemory96MiB();
  if (argc == 2 && std::wstring(argv[1]) == L"--child-sleep-long") return ChildSleepLong();
  if (argc == 2 && std::wstring(argv[1]) == L"--self-test-json") return SelfTest();
  return 2;
}
