#define DIRECTINPUT_VERSION 0x0800
#include <windows.h>
#include <dinput.h>

int wmain() {
  // This validation host deliberately does NOT load MalGuardSample.asi itself.
  // It imports dinput8.dll so a real ASI loader proxy can be placed beside the
  // executable and become responsible for discovering/loading the staged ASI.
  LPDIRECTINPUT8W directInput = nullptr;
  const HRESULT hr = DirectInput8Create(
      GetModuleHandleW(nullptr),
      DIRECTINPUT_VERSION,
      IID_IDirectInput8W,
      reinterpret_cast<void**>(&directInput),
      nullptr);

  if (directInput != nullptr) {
    directInput->Release();
  }

  // Ultimate ASI Loader v9.7.0 supports deterministic deferred plugin loading
  // through LoadFromAPI=GetSystemTimeAsFileTime. Calling this Win32 API from
  // the executable exercises that documented loader path without directly
  // loading the ASI from this fixture.
  FILETIME fileTime{};
  GetSystemTimeAsFileTime(&fileTime);

  // Keep the process alive long enough for MalGuard's in-container telemetry
  // to prove that both the external loader and staged ASI are mapped modules.
  Sleep(30000);

  // DirectInput initialization is not the acceptance signal. The external
  // loader/module telemetry is, so avoid making headless CI depend on input HW.
  (void)hr;
  return 0;
}
