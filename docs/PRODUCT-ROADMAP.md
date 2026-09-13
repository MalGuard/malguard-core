# MalGuard Product Roadmap

## Milestone 0.9 - Core Security Foundation

Status: Release candidate.

Exit criteria:
- Scanner core frozen and regression-protected.
- Engineering suite green on every change.
- Real-browser acceptance checks completed.
- Private source repository and CI enabled.
- Critical/high known defects at zero for the accepted scope.

## Milestone 1.0 - Scanner Release

- Product packaging and installer foundation.
- Secure update metadata.
- Signed release process.
- Stable Free/Pro entitlement boundary.
- Crash/error reporting with privacy controls.
- User-facing quarantine/review concepts prepared for the desktop guard.

## Milestone 1.5 - Game Guard

- Desktop companion/agent.
- Watched game/mod directories.
- New or changed mods enter a pending/locked state before game use.
- Scan-before-allow policy.
- Fail-closed behavior for unresolved high-risk files.
- Quarantine and safe restore.
- Runtime attribution: game -> mod/package -> file -> detection reason -> action.
- Protection health Self-Test inside the product.

## Milestone 2.0 - Behavioral Protection

- Disposable isolated analysis environment.
- Strict CPU, memory, time and filesystem limits.
- Restricted/controlled network behavior.
- Behavioral event collection and scoring.
- Automatic teardown after each analysis.
- Behavioral verdict correlated with static/reputation signals.

## Later product work

- Larger threat-intelligence/reputation corpus.
- Multiple games beyond GTA.
- Windows production release, then macOS adaptation/notarization.
- Commercial account/licensing/payment layer.
- Customer-facing website/domain, downloads, documentation and release notes.
