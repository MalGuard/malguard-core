# MalGuard Desktop 0.6.0-dev

This is the local desktop control service around the hardened MalGuard scanner core, Windows Guard components, threat intelligence and the Sandbox boundary.

## Scan models

The product exposes one **Choose Model** selector rather than separate model tabs:

- **Standard**: normal local scan using the lightweight scanner path. It does not request Sandbox analysis.
- **Plus**: the former deep Pro scan. It runs staged deep/static analysis, correlation and threat intelligence, then automatically sends suspicious or inconclusive results to Sandbox.
- **Pro**: direct Sandbox model. It performs only a narrow file identity/integrity preflight, then hands the sample directly to the isolated Sandbox backend. It does not run the Standard/Plus scanner first.

The internal core still uses the historical `free`/`pro` engine modes for compatibility; those names are implementation details and are not the user-facing product models.

## Implemented

- Local path scanning through the hardened scanner core.
- Standard / Plus / Pro model orchestration with bounded asynchronous session events.
- Real-time directory watcher when a protected game root is configured.
- Fail-closed quarantine and integrity-checked restore.
- Managed install flow with scan-before-release.
- Incident attribution and persistent incident journal.
- MalwareBazaar SHA-256 reputation integration with local cache and secure credential boundary.
- Two-tab local UI: Scanner and Engine Test.
- Sandbox isolation plumbing self-test and Windows Sandbox backend boundary.

## Important Sandbox boundary

Arbitrary untrusted sample execution remains disabled in the release path until the hardened Windows Sandbox acceptance gates pass. Pro therefore fails closed when the release-grade Sandbox is unavailable. A browser Worker or ordinary child process is never presented as a malware Sandbox.

## Development run

`node desktop-app/server.js`

The server binds only to `127.0.0.1` by default.
