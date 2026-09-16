#include <windows.h>
#include <tlhelp32.h>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace {

struct ProcessRow {
  DWORD id{};
  std::wstring name;
};

struct ModuleRow {
  std::wstring name;
  std::wstring file;
};

struct ChildProcess {
  PROCESS_INFORMATION pi{};
  bool started{false};
};

std::string utf8(const std::wstring& value) {
  if (value.empty()) return {};
  const int needed = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
  if (needed <= 0) return {};
  std::string out(static_cast<size_t>(needed), '\0');
  WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), out.data(), needed, nullptr, nullptr);
  return out;
}

std::string json_escape(const std::string& value) {
  std::ostringstream out;
  for (const unsigned char c : value) {
    switch (c) {
      case '\\': out << "\\\\"; break;
      case '"': out << "\\\""; break;
      case '\b': out << "\\b"; break;
      case '\f': out << "\\f"; break;
      case '\n': out << "\\n"; break;
      case '\r': out << "\\r"; break;
      case '\t': out << "\\t"; break;
      default:
        if (c < 0x20) {
          out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c) << std::dec;
        } else {
          out << static_cast<char>(c);
        }
    }
  }
  return out.str();
}

std::string quoted_json(const std::wstring& value) {
  return "\"" + json_escape(utf8(value)) + "\"";
}

std::string iso_now() {
  SYSTEMTIME st{};
  GetSystemTime(&st);
  char buffer[64]{};
  sprintf_s(buffer, "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
  return buffer;
}

std::vector<ProcessRow> snapshot_processes() {
  std::vector<ProcessRow> rows;
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) return rows;
  PROCESSENTRY32W entry{};
  entry.dwSize = sizeof(entry);
  if (Process32FirstW(snap, &entry)) {
    do {
      rows.push_back(ProcessRow{entry.th32ProcessID, entry.szExeFile});
      if (rows.size() >= 300) break;
    } while (Process32NextW(snap, &entry));
  }
  CloseHandle(snap);
  return rows;
}

std::vector<ModuleRow> snapshot_modules(DWORD pid) {
  std::vector<ModuleRow> rows;
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
  if (snap == INVALID_HANDLE_VALUE) return rows;
  MODULEENTRY32W entry{};
  entry.dwSize = sizeof(entry);
  if (Module32FirstW(snap, &entry)) {
    do {
      rows.push_back(ModuleRow{entry.szModule, entry.szExePath});
      if (rows.size() >= 512) break;
    } while (Module32NextW(snap, &entry));
  }
  CloseHandle(snap);
  return rows;
}

std::wstring full_path(const std::wstring& input) {
  DWORD needed = GetFullPathNameW(input.c_str(), 0, nullptr, nullptr);
  if (needed == 0) return input;
  std::wstring output(static_cast<size_t>(needed), L'\0');
  const DWORD written = GetFullPathNameW(input.c_str(), needed, output.data(), nullptr);
  if (written == 0 || written >= needed) return input;
  output.resize(written);
  return output;
}

bool same_path(const std::wstring& a, const std::wstring& b) {
  return _wcsicmp(full_path(a).c_str(), full_path(b).c_str()) == 0;
}

bool module_loaded(const std::vector<ModuleRow>& modules, const std::wstring& sample) {
  return std::any_of(modules.begin(), modules.end(), [&](const ModuleRow& row) {
    return !row.file.empty() && same_path(row.file, sample);
  });
}

bool start_process(const std::wstring& executable, const std::wstring& cwd, ChildProcess& child) {
  std::wstring command = L"\"" + executable + L"\"";
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION pi{};
  const BOOL ok = CreateProcessW(
      executable.c_str(), command.data(), nullptr, nullptr, FALSE,
      CREATE_UNICODE_ENVIRONMENT, nullptr, cwd.c_str(), &startup, &pi);
  if (!ok) return false;
  child.pi = pi;
  child.started = true;
  return true;
}

void close_child(ChildProcess& child, bool terminate) {
  if (!child.started) return;
  if (terminate && WaitForSingleObject(child.pi.hProcess, 0) == WAIT_TIMEOUT) {
    TerminateProcess(child.pi.hProcess, 0);
    WaitForSingleObject(child.pi.hProcess, 3000);
  }
  CloseHandle(child.pi.hThread);
  CloseHandle(child.pi.hProcess);
  child.started = false;
}

std::string process_rows_json(const std::vector<ProcessRow>& rows) {
  std::ostringstream out;
  out << '[';
  for (size_t i = 0; i < rows.size(); ++i) {
    if (i) out << ',';
    out << "{\"Id\":" << rows[i].id
        << ",\"ProcessName\":" << quoted_json(rows[i].name)
        << ",\"Path\":null}";
  }
  out << ']';
  return out.str();
}

std::string module_rows_json(const std::vector<ModuleRow>& rows) {
  std::ostringstream out;
  out << '[';
  for (size_t i = 0; i < rows.size(); ++i) {
    if (i) out << ',';
    out << "{\"ModuleName\":" << quoted_json(rows[i].name)
        << ",\"FileName\":" << quoted_json(rows[i].file) << '}';
  }
  out << ']';
  return out.str();
}

std::wstring lower_extension(const std::wstring& path) {
  std::wstring ext = std::filesystem::path(path).extension().wstring();
  std::transform(ext.begin(), ext.end(), ext.begin(), [](wchar_t c) { return static_cast<wchar_t>(towlower(c)); });
  return ext;
}

bool is_plugin(const std::wstring& ext) {
  return ext == L".asi" || ext == L".dll";
}

bool is_native_executable(const std::wstring& ext) {
  return ext == L".exe" || ext == L".com" || ext == L".scr";
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
  if (argc != 8) return 2;

  const std::wstring samplePath = argv[1];
  const std::wstring gameExecutable = argv[2];
  const std::wstring outputPath = argv[3];
  const std::wstring sessionId = argv[4];
  const int observeSeconds = std::clamp(_wtoi(argv[5]), 3, 60);
  const int startupSeconds = std::clamp(_wtoi(argv[6]), 3, 90);
  const std::wstring contextKind = argv[7];
  const bool realGame = contextKind == L"real-gta";
  if (!realGame && contextKind != L"synthetic-gta-compatible") return 3;

  const std::string startedAt = iso_now();
  const std::wstring gameRoot = std::filesystem::path(gameExecutable).parent_path().wstring();
  const std::wstring ext = lower_extension(samplePath);

  bool attempted = false;
  bool executionStarted = false;
  bool timedOut = false;
  bool fixtureStarted = false;
  bool pluginObserved = false;
  DWORD sampleExitCode = 0;
  bool hasSampleExitCode = false;
  std::wstring executionError;
  std::wstring startupError;

  const auto baselineProcesses = snapshot_processes();
  std::vector<ModuleRow> baselineModules;
  std::vector<ModuleRow> finalModules;
  ChildProcess game{};
  ChildProcess sample{};

  if (!std::filesystem::is_regular_file(gameExecutable) || !std::filesystem::is_regular_file(samplePath)) {
    executionError = L"runtime game executable or staged sample missing";
  } else if (!start_process(gameExecutable, gameRoot, game)) {
    startupError = L"game-context process failed to launch in ProcessContainer";
    executionError = startupError;
  } else {
    const auto startupDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(startupSeconds);
    while (std::chrono::steady_clock::now() < startupDeadline) {
      const DWORD state = WaitForSingleObject(game.pi.hProcess, 500);
      if (state == WAIT_TIMEOUT) {
        fixtureStarted = true;
        break;
      }
      if (state == WAIT_OBJECT_0) break;
    }

    if (!fixtureStarted) {
      startupError = L"game context exited before observation";
      executionError = startupError;
    } else {
      baselineModules = snapshot_modules(game.pi.dwProcessId);
      attempted = true;

      if (is_plugin(ext)) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(observeSeconds);
        while (std::chrono::steady_clock::now() < deadline) {
          if (WaitForSingleObject(game.pi.hProcess, 0) != WAIT_TIMEOUT) break;
          finalModules = snapshot_modules(game.pi.dwProcessId);
          if (module_loaded(finalModules, samplePath)) {
            pluginObserved = true;
            executionStarted = true;
            break;
          }
          Sleep(500);
        }
      } else if (is_native_executable(ext)) {
        const std::wstring sampleRoot = std::filesystem::path(samplePath).parent_path().wstring();
        if (start_process(samplePath, sampleRoot, sample)) {
          executionStarted = true;
          const DWORD wait = WaitForSingleObject(sample.pi.hProcess, static_cast<DWORD>(observeSeconds * 1000));
          if (wait == WAIT_TIMEOUT) {
            timedOut = true;
          } else if (wait == WAIT_OBJECT_0 && GetExitCodeProcess(sample.pi.hProcess, &sampleExitCode)) {
            hasSampleExitCode = true;
          }
        } else {
          executionError = L"native sample process failed to launch";
        }
      } else {
        executionError = L"sample type requires Windows Sandbox fallback";
      }

      if (WaitForSingleObject(game.pi.hProcess, 0) == WAIT_TIMEOUT) {
        finalModules = snapshot_modules(game.pi.dwProcessId);
        if (is_plugin(ext) && !pluginObserved && module_loaded(finalModules, samplePath)) {
          pluginObserved = true;
          executionStarted = true;
        }
      }
    }
  }

  const auto finalProcesses = snapshot_processes();
  const std::string finishedAt = iso_now();

  std::ostringstream json;
  json << '{'
       << "\"schemaVersion\":\"1.1.0\","
       << "\"sessionId\":" << quoted_json(sessionId) << ','
       << "\"startedAt\":\"" << startedAt << "\","
       << "\"finishedAt\":\"" << finishedAt << "\","
       << "\"samplePath\":" << quoted_json(samplePath) << ','
       << "\"networkPolicy\":\"disabled-by-processcontainer\","
       << "\"execution\":{"
       << "\"attempted\":" << (attempted ? "true" : "false") << ','
       << "\"started\":" << (executionStarted ? "true" : "false") << ','
       << "\"exitCode\":";
  if (hasSampleExitCode) json << sampleExitCode; else json << "null";
  json << ",\"timedOut\":" << (timedOut ? "true" : "false")
       << ",\"cpuBudgetExceeded\":false,\"outputQuotaExceeded\":false,\"error\":";
  if (executionError.empty()) json << "null"; else json << quoted_json(executionError);
  json << "},"
       << "\"baselineProcesses\":" << process_rows_json(baselineProcesses) << ','
       << "\"finalProcesses\":" << process_rows_json(finalProcesses) << ','
       << "\"recentFiles\":[],"
       << "\"gameContext\":{"
       << "\"enabled\":true,"
       << "\"contextKind\":" << quoted_json(contextKind) << ','
       << "\"realGame\":" << (realGame ? "true" : "false") << ','
       << "\"syntheticFixture\":" << (realGame ? "false" : "true") << ','
       << "\"fixtureStarted\":" << (fixtureStarted ? "true" : "false") << ','
       << "\"containment\":\"processcontainer\","
       << "\"requiresNestedVirtualization\":false,"
       << "\"hostGameReadOnly\":true,"
       << "\"ephemeralGameClone\":true,"
       << "\"processId\":" << (game.started ? game.pi.dwProcessId : 0) << ','
       << "\"processName\":" << quoted_json(std::filesystem::path(gameExecutable).filename().wstring()) << ','
       << "\"executable\":" << quoted_json(gameExecutable) << ','
       << "\"baselineModules\":" << module_rows_json(baselineModules) << ','
       << "\"finalModules\":" << module_rows_json(finalModules) << ','
       << "\"pluginObserved\":" << (pluginObserved ? "true" : "false") << ','
       << "\"startupError\":";
  if (startupError.empty()) json << "null"; else json << quoted_json(startupError);
  json << "}}";

  try {
    std::filesystem::create_directories(std::filesystem::path(outputPath).parent_path());
    const std::filesystem::path tempPath = std::filesystem::path(outputPath).wstring() + L".tmp";
    {
      std::ofstream output(tempPath, std::ios::binary | std::ios::trunc);
      output << json.str();
      if (!output.good()) return 30;
    }
    std::error_code ec;
    std::filesystem::remove(outputPath, ec);
    std::filesystem::rename(tempPath, outputPath, ec);
    if (ec) return 31;
  } catch (...) {
    return 32;
  }

  close_child(sample, true);
  close_child(game, true);
  return 0;
}
