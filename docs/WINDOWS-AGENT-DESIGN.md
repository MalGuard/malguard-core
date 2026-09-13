# MalGuard Windows Guard v0.1

This milestone introduces a real user-space desktop-agent prototype that can watch configured game/mod folders, revalidate file identity around scans, quarantine non-safe files, restore quarantined files explicitly, and perform MalGuard-managed installs through a scan-before-release staging path.

## Security properties

- Game roots are explicit and path-bounded.
- Quarantine storage must live outside watched game roots.
- Symbolic links are rejected by file-integrity checks.
- File SHA-256 and size are recorded before and after scanning.
- A file that changes during scanning becomes `INCONCLUSIVE` and is contained fail-closed.
- `SUSPICIOUS`, `MALICIOUS`, and `INCONCLUSIVE` files are removed from the active game path into quarantine.
- Restore verifies quarantine integrity and refuses to overwrite an existing target.
- Managed installs stage and scan a copy before it is moved into a game folder.

## Important boundary

The watcher is a user-space agent. It does **not** provide a kernel minifilter, filesystem driver, or guaranteed pre-load interception for files copied directly into a watched folder by another program. There is an unavoidable race between an out-of-band write and a user-space watcher receiving the event.

For files installed through `ManagedInstallGuard`, MalGuard can provide a stronger scan-before-release guarantee because the file stays in staging until a SAFE verdict is produced.

A future signed Windows service may improve reliability and lifecycle management. Kernel-level interception is intentionally not claimed in this milestone.
