# Contributing to MalGuard

MalGuard accepts defensive-security contributions through reviewed pull requests.

## Safety requirements

- Do not commit, upload, download, or execute real malware.
- Use harmless synthetic fixtures for security tests.
- Do not add secrets, API tokens, private keys, certificates, PFX files, credentials, or personal data.
- Do not weaken fail-closed behavior to make a test pass.
- Do not introduce hidden network access, telemetry, installers, or update behavior.
- Do not bypass release provenance, integrity, update, or code-signing controls.

## Development workflow

1. Create a branch from the current `main`.
2. Make the smallest reviewable change.
3. Add or update tests for security-sensitive behavior.
4. Run `node tests/run-all.js` and relevant platform tests.
5. Open a pull request.
6. Require review and green CI before merge.

Security-sensitive build, workflow, installer, updater, isolation, and signing changes require especially careful review.

## Maintainer security

Maintainers must use multi-factor authentication for repository access. Release approval and code-signing approval are separate responsibilities even when one maintainer temporarily holds both roles.
