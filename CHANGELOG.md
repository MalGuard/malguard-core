# Changelog

Notable changes are documented here in the spirit of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This is a source-history record; **an entry does not establish that a signed or production-certified binary was published**. The authoritative current source version is in `DESKTOP-VERSION` and `package.json`.

## [Unreleased]

### Documentation and community health
- Clarified developer onboarding, evidence-based feature scope, security limitations and module architecture.
- Added a public maintenance-evidence index, a source-grounded roadmap, feature-request template and conduct guidelines.
- Added private disclosure contact and explicit best-effort pre-release support language.
- Documented published GitHub pre-release notes in this changelog (including `0.8.0-beta.2`) so release history matches GitHub Releases.
- Documented that `gitBlobSha` in `desktop-app/sandbox/isolation-readiness.js` uses SHA-1 only as a Git blob object id, not as a security hash.
- Recorded an honest contributor warnings policy in `CONTRIBUTING.md` without claiming a project-wide ESLint setup.

### Verified development history (selected merged pull requests)
- [#123](https://github.com/MalGuard/malguard-core/pull/123): improved contributor onboarding and safe public issue reporting.
- [#121](https://github.com/MalGuard/malguard-core/pull/121): added read-only MalGuard MCP tools.
- [#117](https://github.com/MalGuard/malguard-core/pull/117): integrated Fusion Engine 2.0 and multi-engine scan changes.

These links identify merged source changes, **not** independently verified published GitHub releases or user adoption.

## Published GitHub pre-releases (source-aligned notes)

These entries describe **published GitHub Releases** that already exist. They are pre-release / preview artifacts. An entry here does **not** claim Authenticode signing, production certification, or that the tagged commit is an ancestor of current `main`.

### [0.8.0-beta.7 telemetry preview] - 2026-09-26 — tag `telemetry-preview-72ec93ef`
- Unsigned Windows x64 telemetry preview for manual testing (asset names report build `0.8.0-beta.7`).
- Release notes record TSH Telemetry PASS, TSH Pro PASS, Security CI PASS, and Windows install/runtime verification PASS for commit `72ec93ef223ec62e3a8df5df9d3c0a536bae41f4`.
- Companion `.sha256` published with the installer.

### [0.8.0-beta.7 TSH Pro preview] - 2026-09-26 — tag `tsh-pro-preview-c3d0d398`
- Verified TSH Pro Windows x64 preview from commit `c3d0d398956607b5a7b1aebc141452f241f0870a` (unsigned).
- Release notes record TSH Pro no-Sandbox scan PASS, Security CI PASS, installer build PASS, and install/runtime self-test PASS.

### [0.8.0-beta.2] - 2026-09-25 — tag `v0.8.0-beta.2`
- Unsigned Windows x64 setup preview (`MalGuard-Setup-0.8.0-beta.2-windows-x64.1.exe`) with published SHA-256 companion file.
- Source commit `6bc4c19468c9953c843a14a118b862c9e9a62447` (merge of [#110](https://github.com/MalGuard/malguard-core/pull/110)): completes the bounded metadata-only AI evidence path for model scans, with explicit opt-out, no raw file bytes, timeout/fail-closed behavior, and existing sandbox isolation preserved.
- Preceding 0.8 work on that line included GTA simulation packaging and hybrid isolation merges (#104–#108, #102). This tag is a published pre-release snapshot; it is not asserted to be an ancestor of current `main`.

### [App Offline Preview 0.2.0] - 2026-09-23 — tags `app-v0.2.0-offline-preview.2`, `app-v0.2.0-offline-preview.1`
- Offline preview packages that bundle a locked snapshot of the official MalGuard production site UI into native containers (Android APK, Windows setup, macOS zip; `.2` also ships Linux AppImage/DEB).
- iOS asset is simulator-only. Windows/macOS previews are not production-signed.

### [App Preview 0.1.0] - 2026-09-23 — tags `malguard-app-v0.1.0-preview`, `app-v0.1.0-preview.1`
- Native app-shell previews using the official MalGuard production website as the application UI (Android/Windows/macOS previews; iOS simulator-only).

### [0.6.1-beta.1 unsigned preview] - 2026-09-20 — tag `v0.6.1-beta.1-unsigned-preview`
- Unsigned Windows x64 and ARM64 setup preview from commit `9bd450df2345eb2f9c9025b05f3d21bef8e43a5d`, with published SHA-256 digests. Not Authenticode-signed.

## Historical engineering notes (preserved from the previous changelog)

The following entries predate this documentation update. Their version headings describe development milestones; they do not override the current source version or prove tagged releases.

## Desktop 0.6.1-dev — Windows acceptance harness
- Added a synthetic-only Windows acceptance runner that recompiles the native containment probe and Windows service, runs the full regression suite, and emits a machine-readable JSON result.
- Fixed the Sandbox release gate so Windows-native containment and isolation self-tests can unlock `releaseGrade` only for the current process after both probes actually pass; no stale disk flag is trusted.
- Re-reads Sandbox capabilities after native probes, fixing the previous impossible-to-reach `releaseReady=true` state.
- The acceptance harness never installs the Windows service, never accepts an arbitrary executable/sample, and never enables experimental detonation.
- Engineering Hardening suite expanded to 32/32 programs PASS locally. The harness itself still must be executed on a real Windows host before Windows-native acceptance can be claimed.

## Desktop 0.6.0-dev — Sandbox hardening and native validation gates
- Added strict behavioral telemetry schema validation and conservative behavior scoring that can raise suspicion but never prove SAFE by silence.
- Added bounded result/output quotas, regular-file checks, session cleanup, and preflight-to-staging SHA-256 identity binding.
- Locked arbitrary behavioral execution behind an explicit release-grade gate; experimental flags cannot bypass missing native acceptance.
- Added a Windows Job Object containment self-test probe source using suspended child assignment, hard CPU cap configuration, memory limit, kill-on-close, and forced termination.
- Added a synthetic Windows Sandbox isolation self-test path that validates read-only input mapping, writable isolated output, disabled networking route, and disposable VM launch without detonating an untrusted sample.
- Engineering Hardening suite expanded to 31/31 programs PASS locally. Windows-native compile/run and Windows Sandbox nested-virtualization validation remain pending.

## 0.3.0-dev — Scanner acceptance + real-time guard hardening
- Scanner Core: mandatory SHA-256 identity, byte-size consistency, bounded rules thresholds, runtime/result envelope attestation.
- Desktop scan path: symlink rejection and post-scan SHA-256 revalidation.
- Guard: baseline scanning of pre-existing active files, watcher health/reconciliation, protected-file scope filter.
- Quarantine: strict UUID IDs, trusted payload path derivation, allowed-root restore confinement.
- Engineering Hardening suite expanded to 17/17 programs and repeated three times after the hardening changes.

## 0.9.0-rc.1 - 2026-09-12

### Security baseline
- Hardened Worker startup reservation against concurrent scan races.
- Enforced fail-closed behavior when official rule coverage or Pro multilayer coverage is unavailable.
- Strengthened Worker result schema, protocol, mode and integration-version validation.
- Revalidated actual input sizes instead of trusting declared metadata.
- Rejected invalid scan modes instead of silently normalizing them.
- Added live component Self-Test and mutation sensitivity checks.
- Expanded malformed ZIP fuzzing, PE adversarial fuzzing and security mutation testing.
- Added phone/browser validation harness for HTTPS browser verification.

### Validation
- Complete local Engineering Hardening suite passes 13/13 programs.

## Windows Guard v0.1 user-space agent
- Added real recursive user-space filesystem watcher prototype.
- Added agent/core protocol handshake and explicit capability/limitation reporting.
- Added SHA-256 pre/post scan revalidation to contain files that change during analysis.
- Added quarantine manifests, integrity-checked restore, and no-overwrite restore policy.
- Added managed install staging for scan-before-release installs into configured game roots.
- Added Windows Guard regression coverage to the Engineering Hardening suite.
- This milestone does not claim kernel/minifilter interception or guaranteed pre-load blocking for out-of-band file writes.

## 0.2.0-dev — Product-first desktop integration
- Added an actual localhost MalGuard Desktop application service and two-tab control UI.
- Added Node scanner bridge into the existing hardened Free/Pro scanning pipeline.
- Wired Windows Guard watcher, quarantine/restore, managed install and incident attribution into the app API.
- Added Sandbox Controller isolation probe and a fail-closed gate that refuses arbitrary untrusted execution until a hardened OS isolation backend exists.
- Added desktop application regression coverage; full suite now contains 16 test programs.

## Desktop 0.4.0-dev
- Added asynchronous Pro scan sessions with bounded progress events.
- Added automatic `Send to Sandbox` routing for suspicious/inconclusive Pro results.
- Added fail-closed sandbox verdict correlation; sandbox telemetry cannot downgrade static suspicion to SAFE.
- Added simple Standard/Pro scanner mode controls and text-first Pro progress timeline.
- Added Pro pipeline unit and localhost API integration tests.

## Desktop 0.5.0-dev — Choose Model semantics
- Replaced the old Standard/Pro mode buttons with one `Choose Model` selector: Standard, Plus, Pro.
- Renamed the former staged Pro workflow to Plus without changing its deep scanner semantics.
- Added direct Pro Sandbox orchestration: identity/integrity preflight then Sandbox handoff, with no normal scanner invocation.
- Added a fail-closed rule that direct Sandbox telemetry may return SAFE only when the backend explicitly declares release-grade assurance.
- Removed the duplicate direct-Sandbox sample control from the Scanner UI; Pro is now the product entry point for direct Sandbox analysis.
- Added model-selection unit, API and UI contract coverage.
