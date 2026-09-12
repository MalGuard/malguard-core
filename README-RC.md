# MalGuard 0.9.0 Release Candidate

MalGuard is a security-focused game-mod scanner currently centered on GTA mod packages and script content. This repository snapshot is the hardened scanner core that will become the foundation for MalGuard's desktop real-time game protection product.

## Current security core

- Static file and package inspection
- ZIP/archive structure validation
- Lua and C# script analysis
- GTA mod/package routing and attribution data
- Extension / magic consistency checks
- Fail-closed verdict handling (`SAFE`, `SUSPICIOUS`, `MALICIOUS`, `INCONCLUSIVE`)
- Free / Pro execution paths with fail-closed degradation
- Dedicated Web Worker scanning and concurrency protection
- Abort, timeout, crash and protocol/schema handling
- Built-in component Self-Test
- Regression corpus, malformed input fuzzing, PE adversarial fuzzing and mutation tests

## Validation baseline

The 0.9.0-rc.1 baseline passes the complete local Engineering Hardening suite:

- 13/13 test programs
- 58/58 regression corpus cases
- 0/22 benign-to-malicious false positives in the benchmark
- 0/23 risk-labelled inputs escaping as SAFE
- 500 random malformed cases + 500 mutated ZIP cases
- 600 randomized PE-shaped adversarial cases
- Worker race/crash/timeout/abort hardening checks
- Security mutation tests and Self-Test integrity checks

Run locally with:

```bash
node tests/run-all.js
```

## Product status

This is a release candidate for the scanner core, not yet the finished commercial MalGuard product. The next product phases are documented in `docs/PRODUCT-ROADMAP.md`.

The remaining major product work includes a desktop guard, real-time mod interception, quarantine/restore, runtime mod attribution, behavioral sandboxing, secure updates, signing, licensing and production telemetry.

## Security position

A clean result is not a guarantee that a file is harmless. MalGuard is designed to fail closed when required analysis cannot be completed confidently. Known limitations are tracked in `SECURITY.md` and the audit notes.
