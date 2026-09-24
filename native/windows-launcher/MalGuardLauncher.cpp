#include <windows.h>
#include <shellapi.h>
#include <winhttp.h>
#include <string>
#include <vector>

namespace {
std::wstring moduleDirectory() {
    std::vector<wchar_t> buffer(32768, L'\0');
    const DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (length == 0 || length >= buffer.size()) return L"";
    std::wstring path(buffer.data(), length);
    const size_t slash = path.find_last_of(L"\\/");
    return slash == std::wstring::npos ? L"" : path.substr(0, slash);
}

bool regularFileExists(const std::wstring& path) {
    const DWORD attrs = GetFileAttributesW(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY) && !(attrs & FILE_ATTRIBUTE_REPARSE_POINT);
}

std::wstring parentDirectory(const std::wstring& value) {
    const size_t slash = value.find_last_of(L"\\/");
    if (slash == std::wstring::npos) return L"";
    return value.substr(0, slash);
}

std::wstring findPackageRoot(std::wstring candidate) {
    for (int depth = 0; depth < 4 && !candidate.empty(); ++depth) {
        if (regularFileExists(candidate + L"\\PACKAGE-MANIFEST.json") &&
            regularFileExists(candidate + L"\\SHA256SUMS.txt") &&
            regularFileExists(candidate + L"\\desktop-app\\server.js")) {
            return candidate;
        }
        candidate = parentDirectory(candidate);
    }
    return L"";
}

void showError(const wchar_t* message) {
    MessageBoxW(nullptr, message, L"MalGuard", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
}

std::wstring startupLogPath() {
    std::vector<wchar_t> localAppData(32768, L'\0');
    const DWORD size = GetEnvironmentVariableW(L"LOCALAPPDATA", localAppData.data(), static_cast<DWORD>(localAppData.size()));
    if (size == 0 || size >= localAppData.size()) return L"";
    const std::wstring directory = std::wstring(localAppData.data(), size) + L"\\MalGuard";
    if (!CreateDirectoryW(directory.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) return L"";
    const std::wstring logs = directory + L"\\logs";
    if (!CreateDirectoryW(logs.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) return L"";
    return logs + L"\\startup-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()) + L".log";
}

bool serverReady() {
    HINTERNET session = WinHttpOpen(L"MalGuard Launcher", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) return false;
    WinHttpSetTimeouts(session, 800, 800, 800, 800);
    HINTERNET connection = WinHttpConnect(session, L"127.0.0.1", 18777, 0);
    HINTERNET request = connection ? WinHttpOpenRequest(connection, L"GET", L"/api/status", nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0) : nullptr;
    bool ready = false;
    if (request && WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) && WinHttpReceiveResponse(request, nullptr)) {
        DWORD status = 0, length = sizeof(status);
        if (WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &status, &length, WINHTTP_NO_HEADER_INDEX) && status == 200) {
            char chunk[1024] = {};
            std::string response;
            DWORD read = 0;
            while (response.size() < 4096 && WinHttpReadData(request, chunk, sizeof(chunk), &read) && read > 0) {
                response.append(chunk, read);
                if (response.find("\"ok\":true") != std::string::npos && response.find("\"product\":\"MalGuard Desktop\"") != std::string::npos) {
                    ready = true;
                    break;
                }
            }
        }
    }
    if (request) WinHttpCloseHandle(request);
    if (connection) WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);
    return ready;
}
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR arguments, int) {
    const bool headlessTest = arguments && std::wstring(arguments) == L"--headless-startup-test";
    const auto reportError = [headlessTest](const std::wstring& message) {
        if (!headlessTest) showError(message.c_str());
    };
    const std::wstring root = findPackageRoot(moduleDirectory());
    if (root.empty()) {
        reportError(L"MalGuard installation is incomplete or has been modified. Reinstall the application.");
        return 2;
    }

    const std::wstring node = root + L"\\desktop-app\\runtime\\node.exe";
    const std::wstring preload = root + L"\\desktop-app\\integrity\\preload.js";
    const std::wstring server = root + L"\\desktop-app\\server.js";
    if (!regularFileExists(node) || !regularFileExists(preload) || !regularFileExists(server)) {
        reportError(L"MalGuard installation is incomplete or has been modified. Reinstall the application.");
        return 3;
    }

    const std::wstring logPath = startupLogPath();
    SECURITY_ATTRIBUTES inheritable{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    HANDLE log = logPath.empty() ? INVALID_HANDLE_VALUE : CreateFileW(logPath.c_str(), GENERIC_WRITE, FILE_SHARE_READ, &inheritable, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (log == INVALID_HANDLE_VALUE) {
        reportError(L"MalGuard could not create its startup diagnostic in %LOCALAPPDATA%\\MalGuard\\logs. Check folder permissions and try again.");
        return 4;
    }

    std::wstring command = L"\"" + node + L"\" --require \"" + preload + L"\" \"" + server + L"\"";
    std::vector<wchar_t> mutableCommand(command.begin(), command.end());
    mutableCommand.push_back(L'\0');

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdOutput = log;
    startup.hStdError = log;
    HANDLE input = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &inheritable, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (input == INVALID_HANDLE_VALUE) {
        CloseHandle(log);
        reportError(L"MalGuard could not set up its local service. Startup diagnostic: " + logPath);
        return 5;
    }
    startup.hStdInput = input;
    PROCESS_INFORMATION process{};
    const DWORD flags = CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP;
    const BOOL created = CreateProcessW(
        nullptr,
        mutableCommand.data(),
        nullptr,
        nullptr,
        TRUE,
        flags,
        nullptr,
        root.c_str(),
        &startup,
        &process
    );

    if (input != INVALID_HANDLE_VALUE) CloseHandle(input);
    if (!created) {
        const DWORD error = GetLastError();
        CloseHandle(log);
        reportError(L"MalGuard could not start its local service (Windows error " + std::to_wstring(error) + L").\nStartup diagnostic: " + logPath);
        return 5;
    }

    CloseHandle(process.hThread);
    CloseHandle(log);
    const ULONGLONG deadline = GetTickCount64() + 20000;
    bool ready = false;
    do {
        if (WaitForSingleObject(process.hProcess, 0) == WAIT_OBJECT_0) break;
        if (serverReady() && WaitForSingleObject(process.hProcess, 0) == WAIT_TIMEOUT) { ready = true; break; }
        Sleep(200);
    } while (GetTickCount64() < deadline);
    if (!ready) {
        const DWORD state = WaitForSingleObject(process.hProcess, 0);
        DWORD exitCode = 0;
        if (state == WAIT_OBJECT_0) GetExitCodeProcess(process.hProcess, &exitCode);
        CloseHandle(process.hProcess);
        reportError(state == WAIT_OBJECT_0
            ? L"MalGuard local service stopped during startup (exit " + std::to_wstring(exitCode) + L"). Reinstall the application if needed.\nStartup diagnostic: " + logPath
            : L"MalGuard local service did not become ready within 20 seconds. Check whether port 18777 is in use.\nStartup diagnostic: " + logPath);
        return state == WAIT_OBJECT_0 ? 6 : 7;
    }
    CloseHandle(process.hProcess);
    if (!headlessTest && reinterpret_cast<INT_PTR>(ShellExecuteW(nullptr, L"open", L"http://127.0.0.1:18777/", nullptr, nullptr, SW_SHOWNORMAL)) <= 32) {
        reportError(L"MalGuard started, but Windows could not open the browser. Visit http://127.0.0.1:18777/ manually.");
        return 8;
    }
    return 0;
}
