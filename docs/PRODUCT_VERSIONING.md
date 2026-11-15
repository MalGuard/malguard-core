# Product and Core versioning

This document distinguishes the public GTA Guard product version from the independently versioned MalGuard Core source package.

## Current identifiers

| Component | Version | Evidence | Meaning |
| --- | --- | --- | --- |
| GTA Guard product | 1.3.2 | Maintainer-provided product version; referenced by the PacketStorm.News/Vulners record | Product-level release identifier. It is not the version of the Core npm package. |
| MalGuard Core source | 0.8.0-beta.7 | `package.json`, `DESKTOP-VERSION`, and `tests/version-consistency.test.js` | Current version declared by this repository's source tree. |

GTA Guard is a product that uses MalGuard Core as an underlying component. The product and the Core component therefore have separate version namespaces. A product release number must not be copied into the Core version field unless the Core itself has actually been released under that version.

## What this does and does not establish

- The Core repository currently declares `0.8.0-beta.7` in both `package.json` and `DESKTOP-VERSION`; the focused version test checks that those values match.
- GTA Guard 1.3.2 is the product version identified by the maintainer and in the external record supplied for review.
- These identifiers alone do **not** prove which exact Core commit was bundled into a particular GTA Guard 1.3.2 installer or binary.
- They do **not** prove that every capability described in an external listing is enabled, shipped, or certified in a particular build.
- They do **not** establish a malware-detection accuracy rate, third-party security audit, or production-grade sandbox certification.

## Required release-provenance improvement

For each future GTA Guard release, publish a release manifest alongside the artifact containing, at minimum:

1. Product name and product version.
2. Exact MalGuard Core repository URL and full commit SHA used to build it.
3. Build workflow/run identifier and build date.
4. Artifact filename, platform/architecture, and SHA-256 digest.
5. Enabled optional components and any capability gates that remain unavailable.
6. Test suite results and host-specific isolation acceptance evidence, clearly separated from synthetic tests.
7. Signing status and signer identity, where applicable.

Do not invent or retrospectively guess a Core commit mapping for an already-published product artifact. If the build provenance is unavailable, state that it is unavailable and add it to the next release process.

## External listing corrections

When describing GTA Guard to an external index or publication:

- Keep the product version as **GTA Guard 1.3.2** only where that release identifier is confirmed by the product release record.
- Describe **MalGuard Core 0.8.0-beta.7** separately as the source component version observed in this repository.
- Link to the official product page, source repository, documentation, and release artifacts where available.
- Describe only capabilities supported by the corresponding release source and tests.
- Do not treat a Vulners AI Score, Confidence label, or estimated uncertainty as a product-quality rating. Vulners documents its AI Score as a predicted vulnerability-severity signal; its value is not a score that a project maintainer can legitimately tune upward.

## Review checklist

- [ ] Product version is backed by an official release record.
- [ ] Core version matches both `package.json` and `DESKTOP-VERSION`.
- [ ] The exact Core commit used by the product artifact is recorded.
- [ ] Artifact SHA-256 is published and independently reproducible or verifiable.
- [ ] Feature claims match the shipped build, not merely planned code.
- [ ] Tests and platform-specific isolation evidence are reported with limitations.
- [ ] External listing links resolve to official project-controlled sources.
