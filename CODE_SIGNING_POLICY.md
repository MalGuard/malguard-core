# Code signing policy

## Current status

MalGuard has submitted an application for free open-source code signing through SignPath Foundation. The application is pending review.

The project must not claim that a release is signed by SignPath Foundation until the application has been accepted and the actual artifact has passed signature verification.

Target OSS signing provider, pending acceptance: SignPath.io / SignPath Foundation.

After acceptance, release and download pages will include the required attribution: "Free code signing provided by SignPath.io, certificate by SignPath Foundation."

## Source and build provenance

- Release artifacts must originate from the canonical `MalGuard/malguard-core` repository.
- Public release candidates must be built from reviewed, merged source.
- CI actions and build dependencies remain pinned and fail closed according to repository policy.
- Artifacts are re-opened and integrity-verified after packaging.
- Source commit/provenance binding must match the expected release source.
- The current Windows workflow creates unsigned engineering release candidates only. Public distribution remains blocked until the resulting installer passes the Authenticode verification gate.

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

Current project roles:

- Committer: repository owner `@MalGuard`
- Reviewer: repository owner `@MalGuard`
- Signing approver: repository owner `@MalGuard`

As the maintainer team grows, these roles should be separated across trusted maintainers where practical.

## Privacy

See [PRIVACY.md](PRIVACY.md).
