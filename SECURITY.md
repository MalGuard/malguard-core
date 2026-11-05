# MalGuard Security Policy

## Scope

MalGuard is a defensive security project. It is designed to reduce risk when inspecting supported game-related files and packages, not to provide a guarantee that any file is harmless.

## Security principles

1. Fail closed when required analysis, integrity, provenance, or isolation evidence is unavailable.
2. Never weaken a security control merely to make a test or release pass.
3. Never download or execute real malware in development, tests, or CI. Use harmless synthetic fixtures only.
4. Treat untrusted files, archives, metadata, offsets, paths, and update metadata as attacker-controlled.
5. Bound resource use where supported and reject malformed or ambiguous inputs safely.
6. Keep update, release, and runtime integrity verification cryptographically bound to expected provenance.
7. Keep release-signing private keys out of GitHub Actions and source control.
8. Require reviewed changes and CI validation before merging security-sensitive changes.

## Isolation

MalGuard includes its own isolation-routing foundations, including MicroVM and portable VM backends. Windows Sandbox may be used as an optional backend on compatible hosts, but it is not a requirement for the MalGuard VM path.

No backend may be treated as release-grade merely because a simulated or contract test passed. Host/backend-specific execution evidence must be truthful, and missing evidence must remain fail closed.

## Release integrity

Release candidates are bound to source provenance and package integrity. Public Windows distribution must follow the project's code-signing policy and must not substitute an unsigned or unverified build for a signed release.

## Supported versions and status

| Version / branch | Security maintenance |
| --- | --- |
| Current `main` development branch (source reports `0.8.0-beta.7`) | Best-effort security fixes and review; no production-support guarantee |
| Older branches, experimental snapshots, and unverified binary artifacts | No stated support commitment |

A pre-release version, a synthetic test pass, or a sandbox configuration is not a claim of release-grade isolation or a signed Windows release. See [CODE_SIGNING_POLICY.md](CODE_SIGNING_POLICY.md).


## Secure design knowledge (maintainer attestation)

The primary maintainer designs and reviews MalGuard changes with classic Saltzer/Schroeder secure-design principles as already practiced in this codebase:

- **Fail-safe defaults** — missing integrity, provenance, isolation, or analysis evidence stays fail-closed rather than silent-allow.
- **Least privilege** — release signing keys stay out of Actions/source control; CI defaults to read-only contents where possible; optional network/threat-intel paths require explicit enablement.
- **Complete mediation** — untrusted paths, archive entries, offsets, and update metadata are re-validated at use, not trusted from earlier steps alone.
- **Allowlist input validation** — supported formats and fields are constrained; malformed or ambiguous inputs are rejected safely with bounded resource use.
- **Economy of mechanism / limited attack surface** — prefer small reviewable changes; do not add hidden network, telemetry, installer, or update behavior.

The maintainer is familiar with common error classes for this Node/desktop stack and the mitigations already reflected in project policy and tests, including:

- Path traversal in archives and file APIs → normalize/allowlist and reject unsafe entries.
- Command injection → no shell for untrusted input; fixed argv where processes are required.
- Prototype pollution → avoid merging untrusted objects into prototypes; validate plain data.
- XSS in UI surfaces → treat scan/metadata strings as untrusted in rendered output.
- Insecure deserialization → do not eval or unserialize untrusted blobs; prefer explicit parsers.
- Supply-chain / unsigned artifacts → integrity hashes, pinned Actions, unsigned preview labeling, and code-signing policy for public Windows distribution.

This section is maintainer attestation tied to existing practices. It does **not** claim a formal course certificate, third-party audit, or production isolation certification.

## Reporting a vulnerability

Email **contact@malguard.site** with a non-sensitive summary, affected source commit/version, expected/observed behavior, and minimal *harmless* reproduction steps. Please do not include malware, credentials, sensitive files, personal data, or exploit payloads. You may also use [GitHub private vulnerability reporting](https://github.com/MalGuard/malguard-core/security/advisories/new) where enabled.

Do **not** file a public issue or publish proof-of-concept details while a report is being assessed. The maintainer will acknowledge reports as capacity allows, triage potential impact, and coordinate a fix and disclosure; no response or remediation SLA is promised.

For ordinary, non-security bugs, use the [non-security issue form](https://github.com/MalGuard/malguard-core/issues/new/choose).
