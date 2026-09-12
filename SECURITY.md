# MalGuard Security Policy

## Current release stage

MalGuard 0.9.0-rc.1 is an engineering release candidate. It is not yet positioned as a replacement for a full endpoint antivirus or EDR product.

## Security principles

1. Fail closed rather than silently report SAFE when required coverage is unavailable.
2. Never execute uploaded or scanned content as part of static analysis.
3. Treat untrusted archive metadata, sizes and offsets as attacker-controlled.
4. Bound CPU, memory, archive expansion and scan time where supported.
5. Isolate browser scanning in a Dedicated Worker and recover from crash/timeout/abort.
6. Keep verdict schemas/version contracts explicit and reject incompatible results.
7. Test security controls with adversarial, fuzz and mutation testing rather than happy-path tests alone.

## Known limitations in 0.9.0-rc.1

- No production desktop real-time game guard yet.
- No production behavioral sandbox yet.
- No Authenticode trust-chain validation.
- No complete PE checksum/authenticity validation.
- No deep extraction of 7z, RAR or RPF.
- No recursive deep nested-archive extraction.
- Script analysis is static/heuristic rather than full compiler/AST/emulation coverage.
- Test corpus is useful but much smaller than commercial AV telemetry corpora.

## Reporting security issues

Do not publish suspected vulnerabilities before they are reviewed. During private development, file them in the private project repository with reproduction information, affected component/version and expected fail-closed behavior.
