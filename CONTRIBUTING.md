# Contributing to MalGuard

MalGuard accepts defensive-security contributions through reviewed pull requests.

**New to the project?** Start with the [contributor quickstart](docs/CONTRIBUTOR_QUICKSTART.md), then browse [open issues](https://github.com/MalGuard/malguard-core/issues). Small documentation improvements and harmless synthetic regression tests are good starting points.

## Safety requirements

- Do not commit, upload, download, or execute real malware.
- Use harmless synthetic fixtures for security tests.
- Do not add secrets, API tokens, private keys, certificates, PFX files, credentials, or personal data.
- Do not weaken fail-closed behavior to make a test pass.
- Do not introduce hidden network access, telemetry, installers, or update behavior.
- Do not bypass release provenance, integrity, update, or code-signing controls.

## Local setup and reviewable tests

Requirements: Git and Node.js 20+. From the repository root:

```bash
node tests/version-consistency.test.js
```

This focused source-contract test does not require downloading samples. For the full suite use `node tests/run-all.js`; many checks are platform-sensitive, so report the actual environment and results. Install optional Node dependencies with `npm install --ignore-scripts` only when needed. Do not claim a test passed unless you ran it.

See [current status and limitations](docs/ROADMAP.md), [community conduct](CODE_OF_CONDUCT.md), and [maintainer evidence](docs/MAINTAINER_EVIDENCE.md).

## Development workflow

1. Create a branch from the current `main`.
2. Make the smallest reviewable change, preferably linked to an open issue.
3. Add or update tests for security-sensitive behavior.
4. Run `node tests/run-all.js` and relevant platform tests, or accurately document which tests you could not run.
5. Open a pull request using the PR template and record the observed results.
6. Require review and green CI before merge.

Security-sensitive build, workflow, installer, updater, isolation, and signing changes require especially careful review.

## Reporting bugs and security issues

- For ordinary, non-sensitive bugs, use the [issue tracker](https://github.com/MalGuard/malguard-core/issues) and harmless synthetic reproductions only.
- For potential vulnerabilities or information that could put users at risk, follow [SECURITY.md](SECURITY.md) and report privately. Never disclose sensitive vulnerability details in public issues.
- A missing scan detection does not prove that a file is safe. Keep claims and test outcomes evidence-based.

## Maintainer security

Maintainers must use multi-factor authentication for repository access. Release approval and code-signing approval are separate responsibilities even when one maintainer temporarily holds both roles.
