# Real-Time Game Guard Design Baseline

This document defines the next major MalGuard subsystem. It is a design target, not functionality claimed by 0.9.0-rc.1.

## Goal

A mod should not become usable by a protected game merely because the user skipped a manual scan.

## Intended decision flow

1. Desktop Guard observes a new or changed mod/package in a protected game location.
2. The item enters `PENDING_SCAN` and is prevented from normal game loading where the operating system integration safely permits this.
3. The existing MalGuard static engine scans the item.
4. Reputation and, when needed, behavioral sandbox results are correlated.
5. Final action:
   - SAFE -> allow/release.
   - SUSPICIOUS -> keep quarantined or require explicit review according to policy.
   - MALICIOUS -> quarantine and block.
   - INCONCLUSIVE -> remain blocked until policy requirements are satisfied.
6. Record attribution: game, mod/package, file, detection reasons, time and action.

## Quarantine rather than destructive deletion

The default defensive action should be quarantine, not irreversible deletion. This prevents the game from loading the item while preserving recovery from false positives and maintaining evidence for investigation.

## Required guard properties

- No silent fail-open if the guard service crashes or loses required coverage.
- Atomic state transitions for watched files.
- Protection against rename/replace/time-of-check-time-of-use races.
- Hash and metadata refresh after every relevant file change.
- Safe handling of locked files and partial downloads/copies.
- Explicit compatibility adapters per game rather than unsafe assumptions.
