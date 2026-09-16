#include <windows.h>

/*
 * MalGuard benign GTA sandbox acceptance fixture.
 * This DLL intentionally performs no network, file, registry, process, or IPC activity.
 * The acceptance test only verifies that the GTA process loaded the module inside
 * the Windows Sandbox-local game clone.
 */
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance;
    (void)reason;
    (void)reserved;
    return TRUE;
}
