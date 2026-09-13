#include <windows.h>
#include <string>
#include <iostream>
#include <sstream>

static constexpr const char* kSchema = "1.0.0";

static bool SetJobLimits(HANDLE job) {
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION ext{};
  ext.BasicLimitInformation.LimitFlags =
      JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
      JOB_OBJECT_LIMIT_PROCESS_MEMORY |
      JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
  ext.BasicLimitInformation.ActiveProcessLimit = 1;
  ext.ProcessMemoryLimit = static_cast<SIZE_T>(64ull * 1024ull * 1024ull);
  if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &ext, sizeof(ext))) return false;

  JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpu{};
  cpu.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
  cpu.CpuRate = 2000; // 20.00% of one scheduling interval budget.
  if (!SetInformationJobObject(job, JobObjectCpuRateControlInformation, &cpu, sizeof(cpu))) return false;
  return true;
}

static int ChildBusyLoop() {
  volatile unsigned long long value = 0;
  const ULONGLONG deadline = GetTickCount64() + 5000;
  while (GetTickCount64() < deadline) {
    value = (value * 1664525ull) + 1013904223ull;
  }
  return static_cast<int>(value & 0x7f);
}

static std::wstring Quote(const std::wstring& value) {
  return L"\"" + value + L"\"";
}

static int SelfTest() {
  wchar_t exePath[MAX_PATH]{};
  const DWORD n = GetModuleFileNameW(nullptr, exePath, MAX_PATH);
  if (n == 0 || n >= MAX_PATH) return 10;

  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  if (!job) return 11;
  const bool limitsConfigured = SetJobLimits(job);
  if (!limitsConfigured) {
    CloseHandle(job);
    return 12;
  }

  std::wstring command = Quote(exePath) + L" --child-busy";
  STARTUPINFOW si{};
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi{};
  const DWORD flags = CREATE_SUSPENDED | CREATE_NO_WINDOW;
  BOOL created = CreateProcessW(
      exePath,
      command.data(),
      nullptr,
      nullptr,
      FALSE,
      flags,
      nullptr,
      nullptr,
      &si,
      &pi);

  bool assigned = false;
  bool resumed = false;
  bool terminated = false;
  if (created) {
    assigned = AssignProcessToJobObject(job, pi.hProcess) == TRUE;
    if (assigned) resumed = ResumeThread(pi.hThread) != static_cast<DWORD>(-1);
    Sleep(750);
    TerminateJobObject(job, 0x4d47);
    const DWORD wait = WaitForSingleObject(pi.hProcess, 3000);
    terminated = wait == WAIT_OBJECT_0;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
  }
  CloseHandle(job);

  const bool ok = created && assigned && resumed && terminated;
  std::ostringstream out;
  out << "{"
      << "\"schemaVersion\":\"" << kSchema << "\","
      << "\"ok\":" << (ok ? "true" : "false") << ","
      << "\"jobObjectCreated\":true,"
      << "\"cpuHardCapConfigured\":true,"
      << "\"memoryLimitConfigured\":true,"
      << "\"killOnCloseConfigured\":true,"
      << "\"processCreatedSuspended\":" << (created ? "true" : "false") << ","
      << "\"assignedBeforeResume\":" << (assigned ? "true" : "false") << ","
      << "\"childResumed\":" << (resumed ? "true" : "false") << ","
      << "\"childTerminated\":" << (terminated ? "true" : "false")
      << "}";
  std::cout << out.str() << std::endl;
  return ok ? 0 : 20;
}

int wmain(int argc, wchar_t** argv) {
  if (argc == 2 && std::wstring(argv[1]) == L"--child-busy") return ChildBusyLoop();
  if (argc == 2 && std::wstring(argv[1]) == L"--self-test-json") return SelfTest();
  return 2;
}
