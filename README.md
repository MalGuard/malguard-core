<div align="center">

<a href="https://malguard.site/"><picture><source media="(prefers-reduced-motion: reduce) and (max-width: 600px)" srcset="https://raw.githubusercontent.com/MalGuard/MalGuard/main/assets/malguard-light-3d-mobile-poster.png" /><source media="(max-width: 600px) and (prefers-reduced-motion: no-preference)" srcset="https://raw.githubusercontent.com/MalGuard/MalGuard/main/assets/malguard-light-3d-mobile.gif" /><source media="(prefers-reduced-motion: reduce)" srcset="https://raw.githubusercontent.com/MalGuard/MalGuard/main/assets/malguard-light-3d-poster.png" /><img src="https://raw.githubusercontent.com/MalGuard/MalGuard/main/assets/malguard-light-3d.gif" alt="The original MalGuard logo in blue and cyan, rendered in 3D — Inspect before you trust." width="100%" /></picture></a>

[Website](https://malguard.site/) · [Documentation](https://malguard.site/docs.html) · [Trust Center](https://malguard.site/trust.html) · [Creator](https://github.com/MalGuard)

</div>

# MalGuard

MalGuard is an open-source defensive security project focused on safer game-mod analysis, local scanning, and fail-closed isolation. GTA Guard is the first product focus.

## Security model

- Static file, archive, script, and PE-oriented inspection
- Extension/magic consistency checks and bounded malformed-input handling
- Fail-closed verdicts: `SAFE`, `SUSPICIOUS`, `MALICIOUS`, and `INCONCLUSIVE`
- Dedicated Worker isolation for browser-side scanning paths
- MalGuard isolation routing with MicroVM / portable VM foundations
- Optional Windows Sandbox backend where available; it is not required for the MalGuard VM path
- Runtime package integrity and sealed-package verification
- Signed update and anti-replay enforcement
- Supply-chain regression checks and pinned CI actions

MalGuard does **not** claim that a clean result proves a file is harmless. Isolation backends and host capabilities are certified independently and fail closed when required evidence is unavailable.

## Safe development rule

Do not add, download, or execute real malware in this repository or its CI. Tests must use harmless synthetic fixtures only.

## Validation

Run the engineering hardening suite locally with:

```bash
node tests/run-all.js
```

Additional release and platform-specific validation runs in GitHub Actions.

## Open source

MalGuard is licensed under the [MIT License](LICENSE).

Contributions are welcome through reviewed pull requests. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security reporting

See [SECURITY.md](SECURITY.md). Do not publish suspected vulnerabilities before maintainers have had a reasonable opportunity to investigate and fix them.

## Privacy

See [PRIVACY.md](PRIVACY.md).

## Code signing policy

See [CODE_SIGNING_POLICY.md](CODE_SIGNING_POLICY.md).

The project is preparing an application for free open-source code signing. Until a signing provider accepts the project and a release passes the required signing/verification gates, unsigned release candidates must not be presented as fully signed public Windows releases.
