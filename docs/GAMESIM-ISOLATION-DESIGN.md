# MalGuard GameSim Isolation

GameSim Isolation is a host-independent behavioral emulation layer for MalGuard.

## Purpose

The environment models a gaming PC rather than a generic sandbox. It exposes a synthetic GTA V / launcher / mod ecosystem to trusted parsers and emulators while keeping untrusted native samples off the real host.

## Security contract

- No untrusted native sample is executed by the host process.
- No real network egress is permitted.
- The simulated world is ephemeral and recreated for each analysis.
- All credentials, session values, wallet-like data and tokens are synthetic decoys only.
- A GameSim-only analysis can produce suspicious/malicious/inconclusive findings, but must never upgrade a sample to SAFE by itself.
- Real Windows execution proof remains a separate capability provided by the Windows Sandbox backend when available.

## Simulated game world

The initial profile contains GTA V, Rockstar Games Launcher, Steam, Discord-like process presence, game/mod directories, user application-data paths, a virtual registry/persistence surface, a synthetic network surface, and harmless decoy session material.

## Roadmap

1. v0.1: world model + fail-closed evidence correlation.
2. v0.2: virtual filesystem and registry event engine.
3. v0.3: simulated process graph and network sinkhole telemetry.
4. v0.4: controlled script interpreter adapters for supported script formats.
5. Future: native instruction/API emulation only if it can preserve the no-host-execution contract.

GameSim must remain clearly labeled as behavioral emulation. It must never claim that a native Windows binary was truly executed unless the Windows Sandbox backend produced real execution proof.
