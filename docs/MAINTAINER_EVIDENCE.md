# Public maintainer and engineering evidence

This page links to **inspectable repository evidence** for reviewers and new contributors. It does **not** claim any specific star count, download volume, external deployment, independent audit, grant approval or project adoption.

## Maintainer responsibilities

- Core project: [MalGuard/malguard-core](https://github.com/MalGuard/malguard-core) (public, MIT-licensed).
- Maintainer account: [@MalGuard](https://github.com/MalGuard). Project founder and lead developer: Mohammadreza Azarderakhsh.
- Active work is visible in [open and merged PRs](https://github.com/MalGuard/malguard-core/pulls?q=is%3Apr), [issues](https://github.com/MalGuard/malguard-core/issues) and [GitHub Actions](https://github.com/MalGuard/malguard-core/actions).
- Selected merged PRs as of 29 October 2026: [#123 contributor onboarding](https://github.com/MalGuard/malguard-core/pull/123), [#121 read-only MCP](https://github.com/MalGuard/malguard-core/pull/121), [#117 Fusion Engine 2.0](https://github.com/MalGuard/malguard-core/pull/117).
- Selected active review work as of that date: [#135 sandbox certification assertion tests](https://github.com/MalGuard/malguard-core/pull/135) and [#136 URLhaus response-contract tests](https://github.com/MalGuard/malguard-core/pull/136). Their current outcome must be checked on GitHub.

## Security design and source-backed validation

- [Security policy](../SECURITY.md), [privacy policy](../PRIVACY.md), [code-signing policy](../CODE_SIGNING_POLICY.md).
- [Root engineering suite](../tests/run-all.js) invokes focused tests for scan resilience, malformed inputs, integrity, sandbox and release gates.
- [Workflow supply-chain test](../tests/workflow-supply-chain.test.js) requires pinned Actions references, read-only default permissions and restricted release workflows.
- [Version consistency test](../tests/version-consistency.test.js) validates the source manifest/version contract.
- [Windows release-candidate workflow](https://github.com/MalGuard/malguard-core/actions/workflows/windows-release-candidate.yml) exists; check individual runs for pass/fail status, do not infer a passing release from its existence.

## Why maintenance assistance matters

Potential uses of Codex or API credits, **subject to any provider approval**, include triaging harmless reproductions, reviewing changes to fail-closed handling, improving regression tests, tracking security-sensitive workflow changes and preparing reviewable release notes. This describes plausible workflows, **not** currently funded or completed tasks.

## Evidence still needed

Independent adoption or usage totals, audited detection effectiveness, and production isolation certificates are **not supplied here**. Do not infer them from commits, PRs, project size, test counts or a passing simulation. Future measurements, if published, should include reproducible methodology and limitations.
