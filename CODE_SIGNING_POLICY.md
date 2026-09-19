# Code signing policy

## Current status

MalGuard is preparing to apply for free open-source code signing. The project must not claim that a release is signed by SignPath Foundation until the application has been accepted and the actual artifact has passed signature verification.

Target OSS signing provider, pending acceptance: SignPath.io / SignPath Foundation.

After acceptance, release and download pages will include the required attribution: "Free code signing provided by SignPath.io, certificate by SignPath Foundation."

## Source and build provenance

- Release artifacts must originate from the canonical `MalGuard/malguard-core` repository.
- Public release candidates must be built from reviewed, merged source.
- CI actions and build dependencies remain pinned and fail closed according to repository policy.
- Artifacts are re-opened and integrity-verified after packaging.
- Source commit/provenance binding must match the expected release source.

## Key handling

- MalGuard release-signing private keys must never be committed to the repository.
- Offline release-signing private keys must never be placed in GitHub Actions.
- Any external signing provider must protect its signing key outside this repository.

## Approval

Every public signing request requires manual approval after CI and integrity verification succeed.

Current project roles:

- Committer: repository owner `@MalGuard`
- Reviewer: repository owner `@MalGuard`
- Signing approver: repository owner `@MalGuard`

As the maintainer team grows, these roles should be separated across trusted maintainers where practical.

## Privacy

See [PRIVACY.md](PRIVACY.md).
