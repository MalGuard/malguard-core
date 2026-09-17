# MalGuard MicroVM

MalGuard MicroVM is the project-owned behavioral isolation environment intended to become the preferred execution backend for Plus and Pro scans.

It is **not** a new CPU hypervisor implementation. MalGuard owns the guest image, launch policy, disposable-disk lifecycle, authenticated guest agent, evidence format, telemetry pipeline, image signing, and release gate. The underlying hardware virtualization layer remains a mature platform component so MalGuard does not add an unnecessary hypervisor attack surface.

## Security contract

A behavioral result is accepted only when all of the following are proven for the current process and current VM image:

- the base VM image is signed with the MalGuard Ed25519 image-signing key and its SHA-256 and size match the signed manifest;
- the VM launcher passes its native containment self-test;
- the VM boots with networking disabled;
- host clipboard integration is disabled;
- the sample input surface is read-only;
- all guest writes go to a disposable overlay that is destroyed after the session;
- the guest agent authenticates to the host-side launcher before telemetry is accepted;
- evidence is bound to the random session ID and the exact signed VM image SHA-256;
- for an analysis session, evidence proves both `sampleAttempted=true` and `sampleStarted=true`;
- telemetry passes the existing MalGuard telemetry schema validation before behavioral scoring.

If any required proof is missing, MalGuard returns an inconclusive fail-closed result. The host must never execute the untrusted sample as a fallback.

## Components

`malguard-microvm-backend.js` provides signed-image trust, session staging, launcher invocation, evidence validation, telemetry validation, and cleanup.

`isolation-backend-router.js` provides a migration path: MalGuard MicroVM is preferred once it is release-grade certified, while the existing Windows Sandbox backend can remain a temporary fallback during development. The fallback can be removed only after MicroVM live acceptance is proven on supported Windows hosts.

The native launcher is expected at `desktop-app/sandbox/bin/MalGuardMicroVMHost.exe`. The signed base image is expected at `desktop-app/sandbox/microvm/malguard-microvm-base.vhdx` together with `.manifest.json` and `.manifest.sig`. These binary artifacts are intentionally not fabricated by unit tests.

## Launcher contract

The launcher accepts a JSON request using `--request <path> --result <path>`. The request contains the session ID, signed image identity, sample identity, observation window, and isolation policy. It must enforce that policy at the virtualization boundary rather than merely reporting that it did so.

For native self-test it accepts `--self-test-json --image <path>` and reports whether hypervisor, memory, and process isolation controls were actually exercised.

## Evidence contract

The result evidence schema is `1.0.0`. Required booleans are:

- `vmBooted`
- `guestAgentAuthenticated`
- `networkDisabled`
- `hostInputReadOnly`
- `disposableOverlay`
- `hostClipboardDisabled`

Analysis sessions additionally require:

- `sampleAttempted`
- `sampleStarted`

Evidence also contains `sessionId` and `imageSha256`. A mismatch rejects the result.

## Non-claims

Unit tests use harmless synthetic fixtures only. They do not prove a real MicroVM boot or real untrusted-file execution. Release-grade status requires a native Windows launcher, a signed guest image, and live acceptance evidence from a virtualization-capable Windows host.
