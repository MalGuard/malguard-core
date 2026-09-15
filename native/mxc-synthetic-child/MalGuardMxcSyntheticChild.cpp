#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <fstream>
#include <sstream>
#include <string>

static bool CanRead(const std::wstring& path) {
  HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) return false;
  CloseHandle(file);
  return true;
}

static bool CanWrite(const std::wstring& path) {
  HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_TEMPORARY, nullptr);
  if (file == INVALID_HANDLE_VALUE) return false;
  const char marker[] = "MALGUARD_SYNTHETIC_MXC_WRITE_CHECK";
  DWORD written = 0;
  const BOOL ok = WriteFile(file, marker, static_cast<DWORD>(sizeof(marker) - 1), &written, nullptr);
  CloseHandle(file);
  DeleteFileW(path.c_str());
  return ok == TRUE && written == sizeof(marker) - 1;
}

static bool TryLoopback(unsigned short port) {
  WSADATA wsa{};
  if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return false;
  SOCKET socketHandle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (socketHandle == INVALID_SOCKET) {
    WSACleanup();
    return false;
  }
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(port);
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  const bool connected = connect(socketHandle, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0;
  closesocket(socketHandle);
  WSACleanup();
  return connected;
}

static bool HostSecretAbsent() {
  wchar_t buffer[8]{};
  SetLastError(ERROR_SUCCESS);
  const DWORD result = GetEnvironmentVariableW(L"MALGUARD_MXC_HOST_SECRET", buffer, static_cast<DWORD>(std::size(buffer)));
  return result == 0 && GetLastError() == ERROR_ENVVAR_NOT_FOUND;
}

static bool WriteReport(const std::wstring& path, bool deniedReadBlocked, bool readonlyWriteBlocked,
                        bool networkDenied, bool hostSecretAbsent) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) return false;
  out << "{"
      << "\"schemaVersion\":\"1.0.0\","
      << "\"syntheticOnly\":true,"
      << "\"deniedReadBlocked\":" << (deniedReadBlocked ? "true" : "false") << ","
      << "\"readonlyWriteBlocked\":" << (readonlyWriteBlocked ? "true" : "false") << ","
      << "\"networkDenied\":" << (networkDenied ? "true" : "false") << ","
      << "\"hostSecretAbsent\":" << (hostSecretAbsent ? "true" : "false")
      << "}";
  return static_cast<bool>(out);
}

int wmain(int argc, wchar_t** argv) {
  if (argc != 5) return 40;
  const std::wstring deniedMarker = argv[1];
  const std::wstring readonlyRoot = argv[2];
  const std::wstring resultPath = argv[3];
  const unsigned long parsedPort = wcstoul(argv[4], nullptr, 10);
  if (parsedPort == 0 || parsedPort > 65535) return 41;

  const bool deniedReadBlocked = !CanRead(deniedMarker);
  const bool readonlyWriteBlocked = !CanWrite(readonlyRoot + L"\\should-not-write.tmp");
  const bool networkDenied = !TryLoopback(static_cast<unsigned short>(parsedPort));
  const bool hostSecretAbsent = HostSecretAbsent();

  if (!WriteReport(resultPath, deniedReadBlocked, readonlyWriteBlocked, networkDenied, hostSecretAbsent)) {
    return 42;
  }
  return deniedReadBlocked && readonlyWriteBlocked && networkDenied && hostSecretAbsent ? 0 : 31;
}
