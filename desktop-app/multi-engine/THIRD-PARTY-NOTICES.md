# Bundled analysis engines

MalGuard Windows builds can bundle pinned official binaries for defensive file analysis.

- YARA-X 1.20.0 — VirusTotal/yara-x — BSD-3-Clause
- capa 9.4.0 — mandiant/capa — Apache-2.0
- FLOSS 3.1.1 — mandiant/flare-floss — Apache-2.0

The build downloads only the locked official GitHub release archives and verifies the SHA-256 recorded in engine-lock.json before extraction.

Microsoft Defender Antivirus is not redistributed by MalGuard. When present on Windows, MalGuard can request a custom scan with remediation disabled and use its result as an independent local signal.
