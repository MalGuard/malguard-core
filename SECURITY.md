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

## Reporting vulnerabilities

Please report suspected vulnerabilities privately to the maintainers before public disclosure. Include the affected commit/version, reproduction steps using harmless fixtures, expected behavior, and observed behavior. Do not attach real malware.

After the repository is public, use GitHub's private vulnerability reporting feature when it is available for this repository.
