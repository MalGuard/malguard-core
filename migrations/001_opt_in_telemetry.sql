-- Explicit operator application only. Never run automatically on app/API startup.
BEGIN;
CREATE TABLE IF NOT EXISTS telemetry_schema_migrations (version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE installations (
  installation_id uuid PRIMARY KEY,
  credential_hash text NOT NULL CHECK (credential_hash ~ '^[a-f0-9]{64}$'),
  identity_type text NOT NULL CHECK (identity_type='anonymous'),
  malguard_version varchar(64) NOT NULL,
  malguard_build varchar(160), device_manufacturer varchar(160), device_model varchar(160),
  cpu_model varchar(160), cpu_cores integer CHECK(cpu_cores BETWEEN 1 AND 4096),
  cpu_threads integer CHECK(cpu_threads BETWEEN 1 AND 8192), ram_bytes bigint CHECK(ram_bytes BETWEEN 1 AND 1125899906842624),
  gpu_model varchar(160), windows_edition varchar(160), windows_version varchar(160), windows_build varchar(160),
  architecture varchar(8), app_language varchar(32),
  diagnostics_consent boolean NOT NULL CHECK(diagnostics_consent), region_consent boolean NOT NULL DEFAULT false,
  country varchar(2), region varchar(64), install_status varchar(16), first_launch_status varchar(16),
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  last_health_check_at timestamptz,
  CHECK(region_consent OR (country IS NULL AND region IS NULL))
);
CREATE TABLE installation_capabilities (
  installation_id uuid PRIMARY KEY REFERENCES installations ON DELETE CASCADE,
  windows_sandbox_available boolean, virtualization_available boolean, defender_available boolean,
  yara_x_available boolean, capa_available boolean, malguard_ai_available boolean,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE email_notifications (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  installation_id uuid NOT NULL REFERENCES installations ON DELETE CASCADE,
  event_type text NOT NULL CHECK(event_type='registration'),
  status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','retrying','sent','failed')),
  attempt_count integer NOT NULL DEFAULT 0,
  first_attempt_at timestamptz, last_attempt_at timestamptz, sent_at timestamptz,
  failure_code varchar(40), created_at timestamptz NOT NULL DEFAULT now(),
  -- Frozen consented payload; retries cannot change the provider's idempotent request body.
  payload jsonb NOT NULL,
  UNIQUE(installation_id,event_type)
);
-- No device data or credentials: temporary protection against delayed registration replay.
CREATE TABLE telemetry_deletions (installation_id uuid PRIMARY KEY, expires_at timestamptz NOT NULL DEFAULT now()+interval '30 days');
-- Shared global counters, deliberately not keyed by IP or device fingerprint.
CREATE TABLE telemetry_rate_limits (scope text PRIMARY KEY, window_start timestamptz NOT NULL, requests integer NOT NULL);
CREATE INDEX installations_updated_idx ON installations(updated_at);
CREATE INDEX notifications_pending_idx ON email_notifications(status,created_at);
INSERT INTO telemetry_schema_migrations(version) VALUES (1);
COMMIT;
