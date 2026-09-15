#include <windows.h>
#include <cstdlib>
#include <iostream>

int wmain(int argc, wchar_t** argv) {
  DWORD sleepMs = 30000;
  if (argc >= 3 && wcscmp(argv[1], L"--sleep-ms") == 0) {
    const unsigned long parsed = std::wcstoul(argv[2], nullptr, 10);
    if (parsed > 0 && parsed <= 120000) sleepMs = static_cast<DWORD>(parsed);
  }
  std::cout << "MALGUARD_RUNTIME_SYNTHETIC_READY" << std::endl;
  Sleep(sleepMs);
  return 0;
}
