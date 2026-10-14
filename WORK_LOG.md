
## 2026-10-14 — Public 1.3.2 release and automatic signed update completion

Native source c9a9d39f239518d423366f1108d387ca98c83979, source archive SHA-256 16e5e98c2174e255faf9f3ace2803e78db7f106cf08fcefeb6e461f54e7bb1b4. Windows run 38172511467 passed 1,029 tests (2 platform skips), all 18 native install/startup/scheduler/uninstall checks, and 5 bounded setup checks. Linux passed 1,030 tests (1 Windows-only skip), ruff and Windows-platform mypy. Update browser tests passed 35 checks through actual authenticated synthetic jobs. Windows canonical FR read-only progress ACLs are accepted; ordinary users still cannot write completion records.

The update action waits for the actual administrator updater, streams bounded real bytes, verifies signed data and rollback state, compares unique SHA-256 sets, and reports fresh versus known records. Repeated data and rules-only changes have distinct truthful outcomes; failures preserve cached data without claiming success. Static-only analysis and scan_file API remain intact.

Owner explicitly requested removal of the website password and unrestricted public distribution. The verified 34,295,808-byte installer (SHA-256 9f843bd23ad267bdbf96111a219be75ee5ed68e7b85304ef36d710fb4582621d) is published by the website repository with a fixed same-origin path, bounded streaming progress and pre-save SHA-256 verification. Private delivery keys and previous website passwords remain outside public Git. Native GUI UAC interaction on the owner laptop and representative malware-corpus accuracy remain untested.
