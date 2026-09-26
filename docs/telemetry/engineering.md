# Opt-in installation diagnostics engineering record

## Inspected source

Base branch: `test/tsh-pro-real-scan`.
Fetched HEAD: `1977b2209e69705fa8d4273642fb12829ca50658`.
Feature branch: `feature/opt-in-installation-telemetry`.

The Windows launcher starts the sealed local Node service, checks port 18777,
and opens Edge app mode/the browser. npm also uses the health preload; the native
launcher currently uses the integrity preload only. Tauri is a separate locked
website shell with zero native capabilities, not the Node scanner launcher.
No Tauri capability or scanner arbitration change is needed.

The two old metrics modules transmitted after startup using opt-out environment
variables and local sent markers. The legacy hardware endpoint emailed inline,
with neither durable idempotency nor stored consent. They are retired, including
HTTP 410 on the legacy endpoint. Existing sandbox analysis evidence and optional
cloud scanning are not installation analytics and were not changed.

Settings schema 1 rejected version mismatches by returning defaults. Schema 2
preserves watchRoots, quarantineRoot and stagingRoot, adds disabled diagnostics,
and atomically saves the locally generated UUID. A failed migration write still
returns the existing paths with diagnostics disabled. Generic settings updates
cannot write consent. Privacy updates do not stop/restart protection.

## Client boundary

`TelemetryConsent.canSendDiagnostics()` is the only sending gate. It checks
explicit persisted consent and pending deletion, then checks again immediately
before dispatch. Controllers abort on revocation; a generation counter rejects
stale inventory results. Failed persistence during revocation latches the current
process off. If storage is unwritable, persistence cannot be promised across a
restart and the UI reports failure. No sent request can be recalled.

`buildTelemetryPayload` builds registration, heartbeat and engine-status payloads.
The registration snapshot is shared with Preview so inventory changes cannot
silently produce a different send list. CIM queries select only disclosed
properties, with a four-second timeout and bounded output. They run only after
consent. No hardware fingerprint is computed. Compatibility remains null when
not known; enabling analytics does not run a sandbox certification.

Only an HTTPS configured endpoint is accepted. Requests forbid redirects, have
five-second deadlines, and return bounded failure states. No telemetry failure
is intentionally propagated into scanner startup. No endpoint is hardcoded or
enabled in production by this PR. Timers exist only while the local app runs.

The localhost privacy routes require a custom header, an exact loopback Host,
and a matching Origin when present. These controls reject browser cross-origin
forms/preflight and DNS rebinding. They do not claim to protect against a local
process with the user's own permissions. Private credentials are outside the
runtime package, use restrictive file creation modes, and inherit the user's
Windows profile ACL. Windows ACLs still need deployment review.

## Server boundary and routes

Two dynamic route groups keep deployment function count small:

- `POST /api/v1/installations/{register,heartbeat,engine-status,unregister}`
- `POST /api/v1/installations/maintenance` (worker credential only)
- `GET /api/v1/admin/installations`
- `GET /api/v1/admin/installations/:id`
- dashboard: `/api/v1/admin/installations?view=dashboard`

Request bodies are limited to 8192 bytes, strict allowlisted JSON, UUID v4,
bounded numeric/string values, booleans and enumerations. Unknown keys and
client-asserted accounts are rejected. Identity is anonymous only; no account
session integration exists in the inspected scanner. Transport must arrive over
HTTPS at the trusted reverse proxy. Do not expose the origin directly or trust
forwarded headers from an untrusted proxy.

Each installation creates a random 256-bit bearer credential locally. Only its
SHA-256 hash is stored, distinct from the random public UUID. Knowing the UUID
does not authorize reading, updating or deleting an existing record. The initial
registration is self-asserted consent, not remote proof that a person clicked a
button. Abuse protection uses shared Postgres minute counters without IP keys.
The global limit can be exhausted; an operator may add non-identifying edge
limits without weakening consent. API errors contain no SQL/provider details.

Admin access uses HTTP Basic (`admin` plus a random >=256-bit secret) over HTTPS.
The server stores only a SHA-256 verifier in its environment and compares hashes
in constant time. Installation credentials cannot authorize admin access. There
is no admin credential in the UI, URL, source, or desktop package. Use a private
browser session; Basic auth has no application logout/revocation session store.
Rotate the server verifier to revoke access. Consider a managed MFA gateway
before wider administrator access. Dashboard text is escaped; restrictive CSP,
no-store and no-referrer headers prevent executable values and caching.

## SQL and race handling

`migrations/001_opt_in_telemetry.sql` is an explicit, transactional migration.
The schema includes installations, separately normalized capabilities, and
unique registration email events. There are no network identifier fields.
Supporting tables hold a schema version, fixed-scope rate counters and deleted
random-ID tombstones (30 days, no hardware, identity or credential data).

All values use query parameters. Only fixed source-defined column names enter
query text. The Neon driver executes mutation transactions with an advisory lock
per installation followed by the mutation in a new READ COMMITTED statement.
This serializes registration versus deletion, including deletion arriving before
a delayed registration. Embedded SQL tests verify query behavior, not Neon
transport or multi-connection concurrency; staging must verify those separately.

No client timestamp is authoritative. Registration/updates use server time.
Actual install time and a verified last health check are not inferred.

## Email and retention

Registration atomically persists a unique outbox event and returns without
contacting Resend. Authenticated maintenance processes one queued event per
request. A lease prevents overlapping workers; every retry uses the same event
key and frozen email body. Five attempts maximum, two minutes between attempts,
and a 23-hour retry horizon. The 24-hour Resend key window is documented at
https://resend.com/changelog/idempotency-keys . No retry after expiration can
create a second alert. Configuration changes can make provider retries fail;
we do not bypass idempotency to force delivery.

Deletion cascades capabilities and outbox data, revokes the local credential,
and never recreates identity from hardware. Offline deletion is visibly pending
and requires manual retry. Disabling sharing requests this privacy control even
though analytics uploads have stopped. An already delivered/in-flight email
cannot be recalled. Region changes cancel pending notifications carrying old
region data. Maintenance deletes inactive records at 90 days, expires deletion
tombstones at 30 days, and clears completed notification payloads after 7 days.
Operators must schedule it and enforce mailbox/backup retention; see PRIVACY.md.

## Test material and verification limits

All telemetry uses random synthetic IDs, `example.invalid` recipients and injected
fetch functions. SQL tests use PGlite (embedded PostgreSQL) in memory. They do not
prove Neon deployment, provider email delivery, or distributed lock behavior.
The runtime acceptance uses the existing benign Lua configuration reader, which
is statically scanned, not executed. Windows CI runs the client/runtime tests on
Windows and existing TSH Pro builds benign native fixtures using pinned engines.
No real malware, real users, production database, or real notification email is
used. Tauri and public release artifacts are unchanged.
