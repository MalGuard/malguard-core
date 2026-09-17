#include <windows.h>
#include <shellapi.h>
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
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    const std::wstring root = findPackageRoot(moduleDirectory());
    if (root.empty()) {
        showError(L"MalGuard could not resolve its sealed installation directory.");
        return 2;
    }

    const std::wstring node = root + L"\\runtime\\node.exe";
    const std::wstring preload = root + L"\\desktop-app\\integrity\\preload.js";
    const std::wstring server = root + L"\\desktop-app\\server.js";
    if (!regularFileExists(node) || !regularFileExists(preload) || !regularFileExists(server)) {
        showError(L"MalGuard installation is incomplete or has been modified. Reinstall the application.");
        return 3;
    }

    std::wstring command = L"\"" + node + L"\" --require \"" + preload + L"\" \"" + server + L"\"";
    std::vector<wchar_t> mutableCommand(command.begin(), command.end());
    mutableCommand.push_back(L'\0');

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    const DWORD flags = CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP;
    const BOOL created = CreateProcessW(
        nullptr,
        mutableCommand.data(),
        nullptr,
        nullptr,
        FALSE,
        flags,
        nullptr,
        root.c_str(),
        &startup,
        &process
    );

    if (!created) {
        showError(L"MalGuard could not start its protected local scanner service.");
        return 4;
    }

    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    Sleep(1200);
    ShellExecuteW(nullptr, L"open", L"http://127.0.0.1:18777/", nullptr, nullptr, SW_SHOWNORMAL);
    return 0;
}
