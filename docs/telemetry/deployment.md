# Telemetry deployment checklist — human authorization required

This PR does not deploy telemetry, create Neon resources, send email, or change
Beta 7/downloads. The following work remains an explicit operator action.

1. Review the PR and Windows/TSH results. Create a separately authorized staging
   Neon database. Apply `migrations/001_opt_in_telemetry.sql` once using a migration
   role. Never run it automatically on startup. Record migration version 1.
2. Use a separate least-privilege application role with SELECT/INSERT/UPDATE/DELETE
   on these telemetry tables, no schema creation, role changes or unrelated data.
   Retention needs DELETE. Configure provider statement timeouts as well as the
   application's request timeouts.
3. Configure server-only variables below in a reviewed staging deployment. Do not
   add them to Tauri/frontend/runtime configuration or a checked-in `.env` file.
4. Verify platform routing, raw-body size limits, HTTPS forwarding, no public
   origin bypass, and no application request-body/header/IP logging. Review
   Vercel infrastructure log settings, Neon backup retention (<=30 days), and
   mailbox deletion (<=30 days). Source code cannot enforce provider policies.
5. Schedule an authenticated POST to maintenance every two minutes while email
   notifications are desired (one message per invocation). At least daily
   invocation is required for retention even when email is unconfigured. Store
   the worker credential in scheduler secrets; never in a query string.
6. Configure the desktop `MALGUARD_DIAGNOSTICS_ENDPOINT` as the reviewed HTTPS
   origin plus `/api/v1/installations`. This is a public endpoint address, not a
   secret. No installation traffic occurs until explicit local consent.
7. Run synthetic staging integration, distributed register/delete concurrency,
   proxy/log review, Windows UI acceptance and recovery tests. Real notification
   email tests need explicit authorization first. Do not use real user telemetry.
8. Production migration, production env changes and production deployment require
   separate authorization. This PR must not publish a release or alter downloads.

| Variable | Location | Purpose |
|---|---|---|
| `DATABASE_URL` | server only | Neon connection; never log |
| `MALGUARD_TELEMETRY_ENABLED` | server only | Must explicitly equal `1` |
| `MALGUARD_TELEMETRY_ADMIN_TOKEN_SHA256` | server only | SHA-256 of a random admin secret |
| `MALGUARD_TELEMETRY_WORKER_TOKEN_SHA256` | server only | SHA-256 of a separate random worker secret |
| `RESEND_API_KEY` | server only | Optional notification provider key |
| `MALGUARD_INSTALL_NOTIFY_EMAIL` | server only | Authorized recipient |
| `MALGUARD_INSTALL_FROM_EMAIL` | server only | Verified sender |
| `MALGUARD_DIAGNOSTICS_ENDPOINT` | desktop environment | Public HTTPS API base, no credentials |

Generate admin/worker secrets using a cryptographically secure password manager.
Keep their raw values outside the repository. The administrator uses the username
`admin` in the browser's HTTP Basic prompt. The worker uses an Authorization Bearer
header. Their credentials must be different from every installation credential.

Rollback: first disable server telemetry (`MALGUARD_TELEMETRY_ENABLED`), then
remove the desktop endpoint configuration while preserving local consent state.
Do not roll users back to the old opt-out metrics implementation. Do not restore
deleted data into a live telemetry database without applying deletion tombstones
from the current database. Production rollback/schema destruction is not automated.
