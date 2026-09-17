# MalGuard VM isolation strategy

MalGuard no longer treats Windows Sandbox as a mandatory product dependency. The runtime isolation router uses a certified Windows Sandbox backend first when it is available on the current machine, then falls back to the MalGuard-owned VM isolation stack.

The default runtime order is:

1. `windows-sandbox`
2. `microvm`
3. `portable-vm`

A backend is never trusted merely because it exists. It must pass both containment and isolation self-tests in the current process before it can become release-grade. If no backend is certified, MalGuard fails closed and must never execute the untrusted sample directly on the host.

## What “MalGuard VM” means

MalGuard owns the guest image policy, launch policy, disposable-disk lifecycle, guest/host protocol, evidence format, telemetry validation, image trust, release gating, and backend routing. The project intentionally does **not** implement a new CPU hypervisor from scratch. Reusing a mature virtualization layer avoids adding an unnecessary hypervisor attack surface.

There are two MalGuard-owned fallback paths:

- `MalGuard MicroVM`: the preferred project-owned hardware-virtualized backend once its native launcher and signed guest image are present and live-certified.
- `MalGuard portable VM`: a software-emulated fallback that does not require Windows Sandbox or VT-x/AMD-V when configured with its trusted VM engine and verified guest image.

Windows Sandbox support remains as an optional compatibility backend. The dependency is removed; the capability is not deleted.

## Security contract

A behavioral result is accepted only when all of the following are proven for the selected backend and current session:

- the VM/runtime image identity is verified;
- the backend passes its containment self-test;
- the backend passes its isolation self-test;
- networking is disabled for the untrusted execution environment;
- host clipboard integration is disabled or not exposed;
- sample input is read-only from the guest;
- guest writes are disposable and destroyed after the session;
- telemetry/evidence is bound to the random session ID and trusted runtime identity;
- for an analysis session, evidence proves the sample execution was attempted and actually started;
- telemetry passes the MalGuard telemetry schema validation before behavioral scoring.

If any proof is missing, the verdict is inconclusive/fail-closed. The host must never run the sample as a fallback.

## MalGuard MicroVM components

`malguard-microvm-backend.js` implements signed-image trust, session staging, launcher invocation, evidence validation, telemetry validation, and cleanup.

The native launcher is expected at `desktop-app/sandbox/bin/MalGuardMicroVMHost.exe`. The signed base image is expected at `desktop-app/sandbox/microvm/malguard-microvm-base.vhdx` together with `.manifest.json` and `.manifest.sig`.

The launcher accepts `--request <path> --result <path>` for analysis/self-test requests and `--self-test-json --image <path>` for native containment validation. It must enforce policy at the virtualization boundary rather than merely report that it did so.

## Portable VM components

`malguard-vm-backend.js` implements the software-emulated VM path. Its security policy disables networking, monitor/UI integration and writable host shares, exposes the staged sample through read-only media, uses disposable/snapshot guest writes, and accepts telemetry only through the controlled serial protocol.

This backend does not require Windows Sandbox. In software-emulation mode it also does not require VT-x/AMD-V, although performance is lower than hardware virtualization.

## Router behavior

`isolation-backend-router.js` is the single policy point. It prefers a certified Windows Sandbox when available. If Windows Sandbox is absent or fails certification, it attempts MalGuard MicroVM and then the portable MalGuard VM. A backend that fails certification is skipped rather than being treated as usable.

This means machines without Windows Sandbox can still use a MalGuard VM backend once the corresponding trusted runtime artifacts are installed and certified.

## Evidence contract

The MicroVM result evidence schema is `1.0.0`. Required booleans include:

- `vmBooted`
- `guestAgentAuthenticated`
- `networkDisabled`
- `hostInputReadOnly`
- `disposableOverlay`
- `hostClipboardDisabled`

Analysis sessions additionally require:

- `sampleAttempted`
- `sampleStarted`

Evidence also binds the `sessionId` and exact VM image SHA-256. A mismatch rejects the result.

## Current release boundary

The routing code, MicroVM backend contract, portable VM backend, fail-closed policy and regression tests exist in the repository. Unit tests use harmless synthetic fixtures only.

A real MalGuard MicroVM boot is **not** considered proven until the native launcher and signed guest image artifacts are installed and live acceptance succeeds on a supported Windows host. Likewise, the portable VM requires its trusted VM engine and verified guest image. No code path is allowed to pretend those artifacts exist when they do not.
