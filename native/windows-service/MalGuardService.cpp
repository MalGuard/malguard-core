#define UNICODE
#define _UNICODE
#include <windows.h>
#include <string>
#include <vector>
#include <chrono>

static const wchar_t* kServiceName = L"MalGuardGuard";
static const wchar_t* kDisplayName = L"MalGuard Real-Time Protection";
static SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
static SERVICE_STATUS g_status{};
static HANDLE g_stopEvent = nullptr;
static HANDLE g_job = nullptr;
static HANDLE g_childProcess = nullptr;

static void SetServiceState(DWORD state, DWORD win32Exit = NO_ERROR, DWORD waitHint = 0) {
  g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  g_status.dwCurrentState = state;
  g_status.dwWin32ExitCode = win32Exit;
  g_status.dwWaitHint = waitHint;
  g_status.dwControlsAccepted = (state == SERVICE_START_PENDING) ? 0 : (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
  static DWORD checkpoint = 1;
  g_status.dwCheckPoint = (state == SERVICE_RUNNING || state == SERVICE_STOPPED) ? 0 : checkpoint++;
  if (g_statusHandle) SetServiceStatus(g_statusHandle, &g_status);
}

static std::wstring GetModuleDirectory() {
  std::vector<wchar_t> buffer(32768);
  DWORD len = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
  if (!len || len >= buffer.size()) return L"";
  std::wstring full(buffer.data(), len);
  size_t pos = full.find_last_of(L"\\/");
  return pos == std::wstring::npos ? L"" : full.substr(0, pos);
}

static bool FileExists(const std::wstring& p) {
  DWORD attrs = GetFileAttributesW(p.c_str());
  return attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

static void LogEvent(WORD type, const std::wstring& message) {
  HANDLE source = RegisterEventSourceW(nullptr, kServiceName);
  if (!source) return;
  LPCWSTR strings[1] = { message.c_str() };
  ReportEventW(source, type, 0, 1, nullptr, 1, 0, strings, nullptr);
  DeregisterEventSource(source);
}

static bool CreateKillOnCloseJob() {
  g_job = CreateJobObjectW(nullptr, nullptr);
  if (!g_job) return false;
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION info{};
  info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  if (!SetInformationJobObject(g_job, JobObjectExtendedLimitInformation, &info, sizeof(info))) {
    CloseHandle(g_job); g_job = nullptr; return false;
  }
  return true;
}

static bool LaunchGuardChild() {
  const std::wstring base = GetModuleDirectory();
  if (base.empty()) return false;
  const std::wstring node = base + L"\\runtime\\node.exe";
  const std::wstring server = base + L"\\app\\desktop-app\\server.js";
  const std::wstring workDir = base + L"\\app";
  if (!FileExists(node) || !FileExists(server)) {
    LogEvent(EVENTLOG_ERROR_TYPE, L"Bundled runtime or desktop server is missing.");
    return false;
  }

  std::wstring command = L"\"" + node + L"\" \"" + server + L"\"";
  std::vector<wchar_t> mutableCommand(command.begin(), command.end());
  mutableCommand.push_back(L'\0');

  // Add a small service-mode marker while preserving the current environment.
  SetEnvironmentVariableW(L"MALGUARD_SERVICE_MODE", L"1");

  STARTUPINFOW si{};
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi{};
  BOOL ok = CreateProcessW(
      node.c_str(), mutableCommand.data(), nullptr, nullptr, FALSE,
      CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
      nullptr, workDir.c_str(), &si, &pi);
  if (!ok) {
    LogEvent(EVENTLOG_ERROR_TYPE, L"Failed to launch MalGuard desktop guard child process.");
    return false;
  }

  CloseHandle(pi.hThread);
  if (!AssignProcessToJobObject(g_job, pi.hProcess)) {
    TerminateProcess(pi.hProcess, ERROR_ACCESS_DENIED);
    CloseHandle(pi.hProcess);
    LogEvent(EVENTLOG_ERROR_TYPE, L"Failed to place MalGuard child process in kill-on-close job.");
    return false;
  }
  g_childProcess = pi.hProcess;
  return true;
}

static void StopChild() {
  if (g_job) {
    CloseHandle(g_job);  // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE terminates the tree.
    g_job = nullptr;
  }
  if (g_childProcess) {
    CloseHandle(g_childProcess);
    g_childProcess = nullptr;
  }
}

static DWORD WINAPI ServiceControlHandler(DWORD control, DWORD, LPVOID, LPVOID) {
  if (control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN) {
    SetServiceState(SERVICE_STOP_PENDING, NO_ERROR, 5000);
    if (g_stopEvent) SetEvent(g_stopEvent);
    return NO_ERROR;
  }
  return ERROR_CALL_NOT_IMPLEMENTED;
}

static void WINAPI ServiceMain(DWORD, LPWSTR*) {
  g_statusHandle = RegisterServiceCtrlHandlerExW(kServiceName, ServiceControlHandler, nullptr);
  if (!g_statusHandle) return;
  SetServiceState(SERVICE_START_PENDING, NO_ERROR, 5000);

  g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!g_stopEvent || !CreateKillOnCloseJob()) {
    SetServiceState(SERVICE_STOPPED, GetLastError());
    return;
  }

  // Restart budget prevents an infinite crash loop. Five child exits within a
  // 60-second window transitions the Windows service to STOPPED/failure.
  std::vector<std::chrono::steady_clock::time_point> exits;
  if (!LaunchGuardChild()) {
    StopChild();
    SetServiceState(SERVICE_STOPPED, ERROR_FILE_NOT_FOUND);
    return;
  }
  SetServiceState(SERVICE_RUNNING);
  LogEvent(EVENTLOG_INFORMATION_TYPE, L"MalGuard real-time protection service started.");

  HANDLE waits[2] = { g_stopEvent, g_childProcess };
  while (true) {
    DWORD result = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
    if (result == WAIT_OBJECT_0) break;
    if (result != WAIT_OBJECT_0 + 1) {
      LogEvent(EVENTLOG_ERROR_TYPE, L"MalGuard service wait failed.");
      break;
    }

    DWORD exitCode = 0;
    GetExitCodeProcess(g_childProcess, &exitCode);
    CloseHandle(g_childProcess); g_childProcess = nullptr;
    auto now = std::chrono::steady_clock::now();
    exits.push_back(now);
    while (!exits.empty() && std::chrono::duration_cast<std::chrono::seconds>(now - exits.front()).count() > 60) exits.erase(exits.begin());
    if (exits.size() >= 5) {
      LogEvent(EVENTLOG_ERROR_TYPE, L"MalGuard child entered a crash loop; service stopped fail-closed.");
      SetServiceState(SERVICE_STOPPED, ERROR_PROCESS_ABORTED);
      StopChild();
      return;
    }
    Sleep(1000);
    if (!LaunchGuardChild()) {
      SetServiceState(SERVICE_STOPPED, ERROR_PROCESS_ABORTED);
      StopChild();
      return;
    }
    waits[1] = g_childProcess;
  }

  StopChild();
  if (g_stopEvent) { CloseHandle(g_stopEvent); g_stopEvent = nullptr; }
  SetServiceState(SERVICE_STOPPED);
  LogEvent(EVENTLOG_INFORMATION_TYPE, L"MalGuard real-time protection service stopped.");
}

static int InstallService() {
  wchar_t exePath[32768]{};
  DWORD len = GetModuleFileNameW(nullptr, exePath, 32768);
  if (!len || len >= 32768) return 2;
  std::wstring bin = L"\"" + std::wstring(exePath, len) + L"\" --service";

  SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
  if (!scm) return 3;
  SC_HANDLE service = CreateServiceW(
      scm, kServiceName, kDisplayName,
      SERVICE_CHANGE_CONFIG | SERVICE_START | SERVICE_QUERY_STATUS,
      SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
      bin.c_str(), nullptr, nullptr, nullptr, L"LocalSystem", nullptr);
  if (!service) { CloseServiceHandle(scm); return 4; }

  SERVICE_DESCRIPTIONW desc{};
  desc.lpDescription = const_cast<LPWSTR>(L"MalGuard local real-time game mod protection service.");
  ChangeServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, &desc);

  // Delayed auto-start reduces boot contention while preserving automatic guard startup.
  SERVICE_DELAYED_AUTO_START_INFO delayed{};
  delayed.fDelayedAutostart = TRUE;
  ChangeServiceConfig2W(service, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, &delayed);

  CloseServiceHandle(service);
  CloseServiceHandle(scm);
  return 0;
}

static int UninstallService() {
  SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (!scm) return 3;
  SC_HANDLE service = OpenServiceW(scm, kServiceName, DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS);
  if (!service) { CloseServiceHandle(scm); return 4; }
  SERVICE_STATUS status{};
  ControlService(service, SERVICE_CONTROL_STOP, &status);
  BOOL ok = DeleteService(service);
  CloseServiceHandle(service);
  CloseServiceHandle(scm);
  return ok ? 0 : 5;
}

int wmain(int argc, wchar_t** argv) {
  if (argc >= 2 && wcscmp(argv[1], L"--install") == 0) return InstallService();
  if (argc >= 2 && wcscmp(argv[1], L"--uninstall") == 0) return UninstallService();
  if (argc >= 2 && wcscmp(argv[1], L"--service") == 0) {
    SERVICE_TABLE_ENTRYW table[] = {
      { const_cast<LPWSTR>(kServiceName), ServiceMain },
      { nullptr, nullptr }
    };
    return StartServiceCtrlDispatcherW(table) ? 0 : 6;
  }
  return 1;
}
