#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <sddl.h>
#include <userenv.h>
#include <objbase.h>

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

static constexpr const char* kSchema = "1.0.0";
static constexpr DWORD kMemoryLimit = 64ull * 1024ull * 1024ull;
static constexpr DWORD kCpuRate = 2000; // 20% hard cap.

struct ProbeResult {
  bool profileCreated = false;
  bool folderResolved = false;
  bool executableCopied = false;
  bool processCreated = false;
  bool assignedToJobBeforeResume = false;
  bool childCompleted = false;
  bool tokenIsAppContainer = false;
  bool containerWriteAllowed = false;
  bool hostWriteDenied = false;
  bool networkDenied = false;
  bool childProcessBlocked = false;
  bool cleanupCompleted = false;
  DWORD processCreateError = ERROR_SUCCESS;
  DWORD childExitCode = STILL_ACTIVE;
};

static std::wstring Quote(const std::wstring& value) {
  return L"\"" + value + L"\"";
}

static bool WriteTextFile(const std::wstring& path, const std::string& text) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) return false;
  out.write(text.data(), static_cast<std::streamsize>(text.size()));
  return static_cast<bool>(out);
}

static std::string ReadTextFile(const std::wstring& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return {};
  std::ostringstream out;
  out << in.rdbuf();
  return out.str();
}

static bool JsonTrue(const std::string& json, const char* key) {
  const std::string needle = std::string("\"") + key + "\":true";
  return json.find(needle) != std::string::npos;
}

static bool CurrentTokenIsAppContainer() {
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
  DWORD isAppContainer = 0;
  DWORD returned = 0;
  const BOOL ok = GetTokenInformation(token, TokenIsAppContainer, &isAppContainer, sizeof(isAppContainer), &returned);
  CloseHandle(token);
  return ok == TRUE && isAppContainer != 0;
}

static bool TryCreateFile(const std::wstring& path) {
  HANDLE file = CreateFileW(
      path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
      FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, nullptr);
  if (file == INVALID_HANDLE_VALUE) return false;
  const char marker[] = "MALGUARD_SYNTHETIC_APP_CONTAINER_PROBE";
  DWORD written = 0;
  const BOOL wrote = WriteFile(file, marker, static_cast<DWORD>(sizeof(marker) - 1), &written, nullptr);
  CloseHandle(file);
  return wrote == TRUE && written == sizeof(marker) - 1;
}

static bool TryLoopbackConnect(unsigned short port) {
  SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (s == INVALID_SOCKET) return false;
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  const int rc = connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
  closesocket(s);
  return rc == 0;
}

static bool TrySpawnChildProcess() {
  wchar_t systemDir[MAX_PATH]{};
  const UINT n = GetSystemDirectoryW(systemDir, MAX_PATH);
  if (n == 0 || n >= MAX_PATH) return false;
  std::wstring exe = std::wstring(systemDir) + L"\\cmd.exe";
  std::wstring command = Quote(exe) + L" /d /c exit 0";
  STARTUPINFOW si{};
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi{};
  const BOOL created = CreateProcessW(
      exe.c_str(), command.data(), nullptr, nullptr, FALSE,
      CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
  if (!created) return false;
  TerminateProcess(pi.hProcess, 0x4d47);
  WaitForSingleObject(pi.hProcess, 3000);
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  return true;
}

static int ChildProbe(const std::wstring& resultPath, const std::wstring& hostDeniedPath, unsigned short port) {
  WSADATA wsa{};
  const bool winsockReady = WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
  const bool tokenIsAppContainer = CurrentTokenIsAppContainer();
  const bool containerWriteAllowed = TryCreateFile(resultPath + L".writecheck");
  const bool hostWriteDenied = !TryCreateFile(hostDeniedPath);
  const bool networkDenied = winsockReady ? !TryLoopbackConnect(port) : false;
  const bool childProcessBlocked = !TrySpawnChildProcess();
  if (winsockReady) WSACleanup();

  std::ostringstream json;
  json << "{"
       << "\"schemaVersion\":\"" << kSchema << "\","
       << "\"tokenIsAppContainer\":" << (tokenIsAppContainer ? "true" : "false") << ","
       << "\"containerWriteAllowed\":" << (containerWriteAllowed ? "true" : "false") << ","
       << "\"hostWriteDenied\":" << (hostWriteDenied ? "true" : "false") << ","
       << "\"networkDenied\":" << (networkDenied ? "true" : "false") << ","
       << "\"childProcessBlocked\":" << (childProcessBlocked ? "true" : "false")
       << "}";

  if (!WriteTextFile(resultPath, json.str())) return 30;
  return tokenIsAppContainer && containerWriteAllowed && hostWriteDenied && networkDenied && childProcessBlocked ? 0 : 31;
}

static bool ConfigureJob(HANDLE job) {
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION ext{};
  ext.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
                                         JOB_OBJECT_LIMIT_PROCESS_MEMORY |
                                         JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
  ext.ProcessMemoryLimit = static_cast<SIZE_T>(kMemoryLimit);
  ext.BasicLimitInformation.ActiveProcessLimit = 1;
  if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &ext, sizeof(ext))) return false;

  JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpu{};
  cpu.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
  cpu.CpuRate = kCpuRate;
  return SetInformationJobObject(job, JobObjectCpuRateControlInformation, &cpu, sizeof(cpu)) == TRUE;
}

static bool CreateLoopbackListener(SOCKET& listener, unsigned short& port) {
  listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (listener == INVALID_SOCKET) return false;
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0;
  if (bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    closesocket(listener);
    listener = INVALID_SOCKET;
    return false;
  }
  if (listen(listener, 1) != 0) {
    closesocket(listener);
    listener = INVALID_SOCKET;
    return false;
  }
  int len = sizeof(addr);
  if (getsockname(listener, reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
    closesocket(listener);
    listener = INVALID_SOCKET;
    return false;
  }
  port = ntohs(addr.sin_port);
  return port != 0;
}

static int SelfTest() {
  ProbeResult result;
  WSADATA wsa{};
  const bool winsockReady = WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
  if (!winsockReady) return 10;

  const DWORD pid = GetCurrentProcessId();
  const std::wstring profileName = L"MalGuard.NativeSandbox.Probe." + std::to_wstring(pid);
  PSID appContainerSid = nullptr;
  PWSTR sidString = nullptr;
  PWSTR folderPathRaw = nullptr;
  SOCKET listener = INVALID_SOCKET;
  HANDLE job = nullptr;
  LPPROC_THREAD_ATTRIBUTE_LIST attributes = nullptr;
  PROCESS_INFORMATION pi{};
  bool processHandlesOpen = false;
  std::wstring copiedExe;
  std::wstring resultPath;
  std::wstring hostDeniedPath;

  const HRESULT createHr = CreateAppContainerProfile(
      profileName.c_str(), L"MalGuard Native Sandbox Probe",
      L"Synthetic-only AppContainer isolation validation", nullptr, 0, &appContainerSid);
  result.profileCreated = SUCCEEDED(createHr) && appContainerSid != nullptr;

  if (result.profileCreated && ConvertSidToStringSidW(appContainerSid, &sidString)) {
    if (SUCCEEDED(GetAppContainerFolderPath(sidString, &folderPathRaw)) && folderPathRaw) {
      result.folderResolved = true;
      const std::wstring folder(folderPathRaw);
      copiedExe = folder + L"\\MalGuardAppContainerChild.exe";
      resultPath = folder + L"\\probe-result.json";

      wchar_t tempDir[MAX_PATH]{};
      const DWORD tempLen = GetTempPathW(MAX_PATH, tempDir);
      if (tempLen > 0 && tempLen < MAX_PATH) {
        hostDeniedPath = std::wstring(tempDir) + L"MalGuard-AppContainer-Host-Deny-" + std::to_wstring(pid) + L".tmp";
      }

      wchar_t selfPath[MAX_PATH]{};
      const DWORD selfLen = GetModuleFileNameW(nullptr, selfPath, MAX_PATH);
      if (selfLen > 0 && selfLen < MAX_PATH) {
        result.executableCopied = CopyFileW(selfPath, copiedExe.c_str(), FALSE) == TRUE;
      }
    }
  }

  unsigned short port = 0;
  const bool listenerReady = CreateLoopbackListener(listener, port);
  job = CreateJobObjectW(nullptr, nullptr);
  const bool jobReady = job != nullptr && ConfigureJob(job);

  SIZE_T attributeBytes = 0;
  InitializeProcThreadAttributeList(nullptr, 2, 0, &attributeBytes);
  if (attributeBytes > 0) {
    attributes = static_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attributeBytes));
  }
  const bool attrInit = attributes && InitializeProcThreadAttributeList(attributes, 2, 0, &attributeBytes) == TRUE;

  SECURITY_CAPABILITIES securityCapabilities{};
  securityCapabilities.AppContainerSid = appContainerSid;
  securityCapabilities.Capabilities = nullptr;
  securityCapabilities.CapabilityCount = 0;
  securityCapabilities.Reserved = 0;

  DWORD childPolicy = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;
  const bool securityAttr = attrInit && UpdateProcThreadAttribute(
      attributes, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
      &securityCapabilities, sizeof(securityCapabilities), nullptr, nullptr) == TRUE;
  const bool childPolicyAttr = securityAttr && UpdateProcThreadAttribute(
      attributes, 0, PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY,
      &childPolicy, sizeof(childPolicy), nullptr, nullptr) == TRUE;

  if (result.profileCreated && result.folderResolved && result.executableCopied &&
      !hostDeniedPath.empty() && listenerReady && jobReady && childPolicyAttr) {
    STARTUPINFOEXW si{};
    si.StartupInfo.cb = sizeof(si);
    si.lpAttributeList = attributes;
    std::wstring command = Quote(copiedExe) + L" --child-probe " + Quote(resultPath) + L" " + Quote(hostDeniedPath) + L" " + std::to_wstring(port);
    const DWORD flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW;
    const BOOL created = CreateProcessW(
        copiedExe.c_str(), command.data(), nullptr, nullptr, FALSE, flags,
        nullptr, nullptr, &si.StartupInfo, &pi);
    result.processCreated = created == TRUE;
    result.processCreateError = created ? ERROR_SUCCESS : GetLastError();
    if (created) {
      processHandlesOpen = true;
      result.assignedToJobBeforeResume = AssignProcessToJobObject(job, pi.hProcess) == TRUE;
      if (result.assignedToJobBeforeResume && ResumeThread(pi.hThread) != static_cast<DWORD>(-1)) {
        const DWORD wait = WaitForSingleObject(pi.hProcess, 10000);
        if (wait == WAIT_OBJECT_0 && GetExitCodeProcess(pi.hProcess, &result.childExitCode)) {
          result.childCompleted = true;
        }
      }
      if (!result.childCompleted) {
        TerminateJobObject(job, 0x4d47);
        WaitForSingleObject(pi.hProcess, 3000);
      }
    }
  }

  if (result.childCompleted) {
    const std::string childJson = ReadTextFile(resultPath);
    result.tokenIsAppContainer = JsonTrue(childJson, "tokenIsAppContainer");
    result.containerWriteAllowed = JsonTrue(childJson, "containerWriteAllowed");
    result.hostWriteDenied = JsonTrue(childJson, "hostWriteDenied");
    result.networkDenied = JsonTrue(childJson, "networkDenied");
    result.childProcessBlocked = JsonTrue(childJson, "childProcessBlocked");
  }

  if (processHandlesOpen) {
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
  }
  if (attributes) {
    DeleteProcThreadAttributeList(attributes);
    HeapFree(GetProcessHeap(), 0, attributes);
  }
  if (job) CloseHandle(job);
  if (listener != INVALID_SOCKET) closesocket(listener);
  WSACleanup();

  if (!resultPath.empty()) {
    DeleteFileW((resultPath + L".writecheck").c_str());
    DeleteFileW(resultPath.c_str());
  }
  if (!copiedExe.empty()) DeleteFileW(copiedExe.c_str());
  if (!hostDeniedPath.empty()) DeleteFileW(hostDeniedPath.c_str());
  if (folderPathRaw) CoTaskMemFree(folderPathRaw);
  if (sidString) LocalFree(sidString);
  if (appContainerSid) FreeSid(appContainerSid);
  const HRESULT deleteHr = DeleteAppContainerProfile(profileName.c_str());
  result.cleanupCompleted = SUCCEEDED(deleteHr);

  const bool ok = result.profileCreated && result.folderResolved && result.executableCopied &&
      result.processCreated && result.assignedToJobBeforeResume && result.childCompleted &&
      result.childExitCode == 0 && result.tokenIsAppContainer && result.containerWriteAllowed &&
      result.hostWriteDenied && result.networkDenied && result.childProcessBlocked && result.cleanupCompleted;

  std::cout << "{"
            << "\"schemaVersion\":\"" << kSchema << "\","
            << "\"ok\":" << (ok ? "true" : "false") << ","
            << "\"profileCreated\":" << (result.profileCreated ? "true" : "false") << ","
            << "\"folderResolved\":" << (result.folderResolved ? "true" : "false") << ","
            << "\"executableCopied\":" << (result.executableCopied ? "true" : "false") << ","
            << "\"processCreated\":" << (result.processCreated ? "true" : "false") << ","
            << "\"processCreateError\":" << result.processCreateError << ","
            << "\"assignedToJobBeforeResume\":" << (result.assignedToJobBeforeResume ? "true" : "false") << ","
            << "\"childCompleted\":" << (result.childCompleted ? "true" : "false") << ","
            << "\"childExitCode\":" << result.childExitCode << ","
            << "\"tokenIsAppContainer\":" << (result.tokenIsAppContainer ? "true" : "false") << ","
            << "\"containerWriteAllowed\":" << (result.containerWriteAllowed ? "true" : "false") << ","
            << "\"hostWriteDenied\":" << (result.hostWriteDenied ? "true" : "false") << ","
            << "\"networkDenied\":" << (result.networkDenied ? "true" : "false") << ","
            << "\"childProcessBlocked\":" << (result.childProcessBlocked ? "true" : "false") << ","
            << "\"cleanupCompleted\":" << (result.cleanupCompleted ? "true" : "false")
            << "}" << std::endl;
  return ok ? 0 : 20;
}

int wmain(int argc, wchar_t** argv) {
  if (argc == 5 && std::wstring(argv[1]) == L"--child-probe") {
    const unsigned long parsed = wcstoul(argv[4], nullptr, 10);
    if (parsed == 0 || parsed > 65535) return 40;
    return ChildProbe(argv[2], argv[3], static_cast<unsigned short>(parsed));
  }
  if (argc == 2 && std::wstring(argv[1]) == L"--self-test-json") return SelfTest();
  return 2;
}
