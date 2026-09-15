# Windows user-space agent prototype

Implemented in v0.1:
- recursive user-space directory watching
- protocol/version handshake
- SHA-256 identity revalidation around scans
- quarantine with integrity manifest
- explicit restore with no-overwrite safety
- managed install staging for scan-before-release
- incident attribution through the existing Desktop Guard contract

Not claimed:
- kernel/minifilter interception
- guaranteed prevention before a game opens an out-of-band file
- Windows Service installation
- code signing
- process injection or runtime hooking

The implementation uses only Node.js built-ins and is designed to be packaged into the future signed desktop companion.
