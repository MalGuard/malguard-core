# Contributor quickstart

Welcome to MalGuard! This guide is for contributors who want to make a small, reviewable improvement to a defensive, open-source security project.

## Before you start

- Read [CONTRIBUTING.md](../CONTRIBUTING.md), [SECURITY.md](../SECURITY.md), and the [MIT License](../LICENSE).
- Install Git and Node.js 20 or later. Most focused source-contract tests use built-in Node.js modules.
- **Do not download, upload, submit, or execute real malware**, including through GitHub issues or CI. Use harmless synthetic test inputs only.
- Never include tokens, API keys, user files, private logs, or personal information in reports.
- Security vulnerabilities belong in the repository's [private security-reporting channel](https://github.com/MalGuard/malguard-core/security/policy), not public issues.

## Clone and run a small test

```bash
git clone https://github.com/MalGuard/malguard-core.git
cd malguard-core
node --version
node tests/version-consistency.test.js
```

### Windows PowerShell

Run the clone command from the directory where you want the repository. Run the
remaining commands from the repository root:

```powershell
git clone https://github.com/MalGuard/malguard-core.git
Set-Location malguard-core
node --version
node tests/version-consistency.test.js
```

Confirm that `node --version` reports Node.js 20 or later. If the focused test
fails, report your Windows version, Node.js version, exact command, and
sanitized error output. Redact usernames, home-directory paths, tokens, and
personal data. Report potential security vulnerabilities through the
[private security-reporting channel](https://github.com/MalGuard/malguard-core/security/policy),
not a public issue.

The version consistency test is a good first check and does not need a local malware sample. For broader validation on a suitable development machine, run:

```bash
node tests/run-all.js
```

The full suite is extensive and contains platform-dependent checks. If it fails, record the exact failing test, operating system, Node.js version, and sanitized error output. A failed test is **not** evidence that a security control may be disabled. Do not claim the full suite passed if you did not run it.

## Find your first contribution

1. Browse [open issues](https://github.com/MalGuard/malguard-core/issues). If labels are available, start with `good first issue` or `documentation`.
2. Choose a small, unassigned issue. Comment with the proposed approach so work is not duplicated.
3. Prefer a documentation correction, a clearer warning, or a harmless synthetic test. Avoid changing security verdict or isolation policy as a first contribution.
4. Fork the repository or create a feature branch, make the smallest change, and run the relevant focused test.
5. Open a pull request using the PR template. Explain what changed, what you tested, and what remains unverified.
6. Address review feedback. Maintainers decide whether a change is safe to merge.

### Example: documentation-only change

Fix an outdated command or broken relative link, verify the rendered Markdown manually, and open a PR. No product release is triggered by preparing the documentation PR itself.

## Important trust boundaries

- A scan result does **not** guarantee a file is harmless.
- Do not weaken fail-closed behavior, release provenance, unsigned-release warnings, code-signing verification, or supply-chain checks.
- Do not add network traffic, telemetry, dependencies, or scripts without explaining their security and privacy impacts.
- CI and review status must be reported honestly. Only maintainers approve release and signing changes.
- Never test by running an unknown GTA plugin on your normal computer.

## Questions and feedback

Use the [public issue tracker](https://github.com/MalGuard/malguard-core/issues) for non-sensitive contributor questions and reproducible, harmless bugs. Use private vulnerability reporting for potential security issues.
