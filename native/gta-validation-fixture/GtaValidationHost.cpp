#include <windows.h>
#include <filesystem>
#include <string>

namespace {
std::filesystem::path executable_directory() {
  std::wstring buffer(32768, L'\0');
  const DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
  if (length == 0 || length >= buffer.size()) return {};
  buffer.resize(length);
  return std::filesystem::path(buffer).parent_path();
}
}

int wmain() {
  const auto root = executable_directory();
  if (root.empty()) return 10;

  std::filesystem::path plugin = root / L"MalGuardSample.asi";
  if (!std::filesystem::exists(plugin)) plugin = root / L"MalGuardSample.dll";
  if (!std::filesystem::exists(plugin)) return 11;

  HMODULE module = LoadLibraryW(plugin.c_str());
  if (!module) return 12;

  // Keep the harmless plugin loaded long enough for MalGuard's module telemetry
  // to observe it in-process. No network, persistence, injection, or host changes.
  Sleep(30000);
  FreeLibrary(module);
  return 0;
}
