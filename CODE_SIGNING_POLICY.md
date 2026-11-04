# Code signing policy

## Current status

MalGuard applied for free open-source code signing through SignPath Foundation. On 2026-11-04 SignPath Foundation replied that it is not issuing a certificate at this time because the project does not yet show enough public adoption signals (community usage, independent references, sustained engagement). The decision was explicitly not about code quality. MalGuard intends to reapply once the project has broader public recognition.

Until then, **no MalGuard release is signed by SignPath Foundation**. Windows builds are published as clearly labelled Unsigned Previews with SHA-256 checksums and source commits.

The project must not claim that a release is signed by SignPath Foundation until the application has been accepted and the actual artifact has passed signature verification.

Target OSS signing provider (not yet accepted): SignPath.io / SignPath Foundation.

After acceptance, release and download pages will include the required attribution: "Free code signing provided by SignPath.io, certificate by SignPath Foundation."

## Source and build provenance

- Release artifacts must originate from the canonical `MalGuard/malguard-core` repository.
- Public release candidates must be built from reviewed, merged source.
- CI actions and build dependencies remain pinned and fail closed according to repository policy.
- Artifacts are re-opened and integrity-verified after packaging.
- Source commit/provenance binding must match the expected release source.
- The current Windows workflow creates unsigned release candidates. By explicit maintainer decision, an installer may be published as an **Unsigned Preview** only when the release page clearly states that Authenticode is absent and publishes the matching SHA-256 and exact source commit. An unsigned preview must never be described as signed, trusted, production-signed, or equivalent to a future Authenticode release.

## SignPath integration boundary

SignPath configuration identifiers and access tokens are not guessed or pre-created by this repository.

After SignPath Foundation accepts the project, integration must use the organization/project/policy/artifact identifiers supplied by SignPath. Any SignPath API access token must be stored only as an Actions secret or provider-managed credential and must never be committed, printed, copied into release artifacts, or exposed in logs.

The SignPath GitHub Action, if enabled after acceptance, must be pinned to an immutable full commit SHA and its output must pass the repository's Authenticode verification before it can become a public release.

## Key handling

- MalGuard release-signing private keys must never be committed to the repository.
- Offline release-signing private keys must never be placed in GitHub Actions.
- Any external signing provider must protect its signing key outside this repository.
- SignPath-managed Authenticode signing does not replace MalGuard's independent offline Ed25519 release-metadata trust boundary.

## Approval

Every public signing request requires manual approval after CI and integrity verification succeed.

### Team roles

These roles follow the structure SignPath Foundation asks open-source projects to publish:

| Role | Who | Responsibility |
| --- | --- | --- |
| Committers and reviewers | [@MalGuard](https://github.com/MalGuard) (Mohammadreza Azarderakhsh) | Write and review every change merged to `main` |
| Approvers | [@MalGuard](https://github.com/MalGuard) (Mohammadreza Azarderakhsh) | Manually approve each signing request |

All team members are required to use multi-factor authentication on GitHub and on any signing service. As the maintainer team grows, these roles will be separated across trusted maintainers, and outside contributors' changes will always be reviewed by a maintainer before merge.

## Privacy

MalGuard analyses supported files locally by default. Packaged Windows builds may send one anonymous first-launch install count and one coarse compatibility report; both contain no user, device, file, or scan data and both can be disabled. Full details and the opt-out settings are in [PRIVACY.md](PRIVACY.md). No other information is transferred to networked systems unless the user explicitly requests a feature that states it.
