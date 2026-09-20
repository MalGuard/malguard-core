# MalGuard Cloud Sandbox

This component is the server-side isolation boundary intended for MalGuard mobile clients.

## Phase 1 safety boundary

Phase 1 accepts **synthetic harmless fixtures only**. Unknown or user-supplied executables are rejected. This is deliberate: remote execution stays disabled until containment has been independently validated.

Each analysis job must:
- create a fresh ephemeral microVM;
- use deny-all outbound networking;
- expose no public ports;
- receive no repository, signing, update, or production secrets;
- enforce a short timeout and bounded resources;
- return a bounded structured report;
- destroy the environment after the job;
- fail closed if any isolation prerequisite cannot be established.

The mobile client must never describe Phase 1 as malware detonation. It is an isolation-validation service.

## Promotion gate

Execution of untrusted samples must remain disabled until tests demonstrate VM-per-job isolation, deny-all egress, resource/time limits, teardown, no host fallback, and audit logging without sample contents or secrets.
