# MalGuard Desktop Guard v0.1 scaffold

This directory defines the contract between the audited MalGuard scanner core and the future signed desktop companion.

Current scope:
- validated filesystem event schema
- fail-closed containment policy
- incident-report schema for responsible-mod attribution
- explicit native adapter boundary

Not implemented yet:
- real Windows/macOS filesystem monitoring
- OS-level load prevention
- real quarantine/restore storage
- process/runtime telemetry

The browser core must never pretend those native capabilities exist. The native adapter therefore fails explicitly until a real desktop companion implements them.
