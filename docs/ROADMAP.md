# Roadmap and current limitations

This is a public **engineering plan**, not a list of shipped features or a promise of future delivery. Priorities may change as contributors review the issues and code.

## Current, source-backed work

- [#130 — URLhaus threat-intelligence adapter](https://github.com/MalGuard/malguard-core/issues/130): document safe, opt-in handling and regression coverage.
- [#134 — ZIP truncation fail-closed regression](https://github.com/MalGuard/malguard-core/issues/134): synthetic archive edge-case testing.
- [#125 — focused-test documentation](https://github.com/MalGuard/malguard-core/issues/125) and [#124 — Windows PowerShell quickstart](https://github.com/MalGuard/malguard-core/issues/124): reduce newcomer setup friction.
- [#126 — verifying unsigned Windows previews](https://github.com/MalGuard/malguard-core/issues/126): improve provenance information for users.
- [#127 — sanitized bug reports](https://github.com/MalGuard/malguard-core/issues/127): improve bug reproducibility without exposing secrets.

Check issue status before starting work; linked issues may have changed.

## Engineering milestones (proposed, not yet release claims)

1. Maintain a reliably passing, reviewable synthetic regression baseline across supported hosts.
2. Verify and document platform-specific isolation certifications independently; treat missing evidence as a blocker, not as an implicit pass.
3. Harden reproducible source-to-artifact verification and code signing, following [CODE_SIGNING_POLICY.md](../CODE_SIGNING_POLICY.md).
4. Publish accessible examples and bounded, privacy-safe evidence about false positives, failures and limitations **only when measurements exist**.
5. Document and review optional threat-intelligence, GTA simulation and cloud integrations as separate capability-gated features.

## Known limitations

- The current source version is a pre-release (`0.8.0-beta.7`); no general production-safety guarantee is made.
- Behavioral isolation is host- and backend-dependent. Simulated passing tests do not certify arbitrary untrusted execution.
- Optional services, reputation lookups and cloud backends may be unavailable or require credentials, consent and separate deployment.
- A `SAFE` result is not proof of zero malware; unknown or unverifiable findings remain inconclusive.
- Repository code/CI alone do not establish external usage, effectiveness benchmarks, an audit or distribution signing.

## Feedback

Submit [non-security issues](https://github.com/MalGuard/malguard-core/issues/new/choose) or send responsible security reports to **contact@malguard.site**.
