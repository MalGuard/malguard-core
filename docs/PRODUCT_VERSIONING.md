# Product and Core versioning

This document separates the GTA Guard product release, the engine identifier, and the independently versioned MalGuard Core source package. These values describe different things and must not be substituted for one another.

## Current identifiers and evidence

| Identifier | Observed value | Evidence | Interpretation |
| --- | --- | --- | --- |
| GTA Guard product | 1.3.2 | `release/gta-guard-windows.json` in `MalGuard/malguard.github.io` | Public product release identifier recorded by the website. |
| GTA Guard engine | 1.2.2 | The same website release manifest and `cleanroom-v1/source.json` at Core commit `c9a9d39f239518d423366f1108d387ca98c83979` | Engine identifier reported for that product build; not the Core npm package version. |
| Product build source commit | `c9a9d39f239518d423366f1108d387ca98c83979` | Website release manifest; this exact commit exists in `MalGuard/malguard-core`. | The release metadata declares this Core commit as the source commit. This is a project-published provenance claim, not independent proof that the distributed executable was reproducibly built from it. |
| Core package / desktop version | 0.8.0-beta.7 | `package.json`, `DESKTOP-VERSION`, and `tests/version-consistency.test.js` on Core `main` | These two files agree and the focused test checks their equality. |
| Additional Core version file | 0.9.0-rc.1 | `VERSION` on Core `main` | This differs from the package and desktop version. Its intended scope must be identified before it is changed or described as the canonical desktop/package version. |

GTA Guard is a product that uses MalGuard Core. The product version, engine identifier, Core package version, and any other version file have separate meanings unless a release process explicitly binds them.

## Existing GTA Guard 1.3.2 release record

The website release manifest currently records:

- Product version: `1.3.2`.
- Engine version: `1.2.2`.
- Build identifier: `MG-1.3.2-WIN64-c9a9d39f2395`.
- Source commit: `c9a9d39f239518d423366f1108d387ca98c83979`.
- Installer filename: `MalGuard-Setup-x64.exe`.
- SHA-256: `9f843bd23ad267bdbf96111a219be75ee5ed68e7b85304ef36d710fb4582621d`.

The companion `.sha256` text file contains the same digest as the JSON manifest. The exact source commit resolves in the Core repository. The Core commit's clean-room source metadata records app version `1.3.2` and engine version `1.2.2`.

These are useful, internally consistent release records. However, the digest has not been independently recomputed from the installer bytes in this review, and the available GitHub workflow-run lookup returned no run associated with the declared source commit. Therefore, describe the source commit and digest as **published release metadata**, not as independently reproduced build attestation.

## Current publication workflow status

The website workflow `.github/workflows/publish-current-gta-guard-windows.yml` is deliberately disabled by an unconditional `if: `${{ false }}` job guard. Its checked-in configuration also targets a different Core commit and a `0.8.0-beta.7` release tag/name. Do not remove the guard or re-enable this workflow as a quick fix: first reconcile the intended product version, engine version, Core commit, release tag, artifact name, and metadata schema, then review and test the complete Windows build path.

The public website metadata says the 1.3.2 Windows download is enabled, while the checked-in publication workflow says public distribution is paused. Treat this as a release-control inconsistency that requires an explicit owner decision before the workflow is reactivated or the public status is changed.

## What is and is not established

- The website declares a GTA Guard 1.3.2 / engine 1.2.2 release and names an exact Core source commit.
- The named Core commit exists, and its source metadata is consistent with the product and engine identifiers.
- The Core package and desktop version files both declare 0.8.0-beta.7; a separate `VERSION` file declares 0.9.0-rc.1 and needs scope clarification.
- The published website JSON and companion checksum text file agree on the installer digest.
- This review has not independently downloaded and hashed the installer bytes, reproduced the Windows build, or verified a workflow run that generated the published installer.
- A version string, release manifest, clean-room source archive, or static scan cannot by itself prove that every capability in an external listing is enabled, shipped, or certified in a particular binary.
- No malware-detection accuracy rate, third-party security audit, or production-grade sandbox certification is established by these version records.

## Required release-provenance controls

For every future GTA Guard release, the publishing workflow should generate and publish a manifest from the actual successful build job, including:

1. Product name and product version.
2. Engine version and exact Core repository URL plus full commit SHA.
3. Workflow run ID, run URL, build date, and immutable release tag.
4. Artifact filename, platform/architecture, byte size, and SHA-256 calculated from the final installer bytes.
5. A companion checksum file generated from the same artifact.
6. Enabled optional components and capability gates that remain unavailable.
7. Test results and platform-specific isolation acceptance evidence, clearly separating synthetic tests from host-validated tests.
8. Signing status and signer identity, where applicable.

The workflow must fail closed if the checked-out Core SHA differs from the manifest source SHA, if the product/engine version tuple does not match the release configuration, if tests fail, or if the final artifact hash does not match the published checksum. A release manifest should never be hand-edited to claim a build that did not complete.

## External listing corrections

When describing GTA Guard to Packet Storm, Vulners, or another index:

- Identify GTA Guard 1.3.2 as the product release and engine 1.2.2 as the engine identifier recorded for that build.
- Identify the declared Core source commit separately; do not label Core package 0.8.0-beta.7 as GTA Guard's product version.
- Link to the official product page, source repository, documentation, and release metadata.
- Keep feature claims limited to capabilities supported by the corresponding source, build and test evidence.
- Correct stale or ambiguous descriptions through the publisher/index's official correction process. Do not claim that an external listing has been changed until the publisher confirms it.
- Do not treat a Vulners AI Score, Confidence label, or estimated uncertainty as a product-quality rating. A predicted vulnerability-severity score is not a project score and must not be tuned upward.

## Review checklist

- [x] Product version and engine version are recorded in the website release manifest.
- [x] The declared Core source commit exists in the Core repository.
- [x] The website JSON and companion checksum text file contain the same SHA-256.
- [ ] Installer bytes independently hashed against the published digest.
- [ ] Build workflow/run independently tied to the published installer.
- [ ] `VERSION` versus `DESKTOP-VERSION` scope resolved.
- [ ] Website public-download status reconciled with the disabled publication workflow.
- [ ] Future workflow generates provenance from the actual successful build.
- [ ] External listing corrections submitted and confirmed by the publisher.
