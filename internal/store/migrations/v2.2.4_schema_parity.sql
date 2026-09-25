-- v2.2.4_schema_parity.sql
--
-- Brings the CE schema in line with what the CE store code reads and writes.
-- The v2.0 baseline was cut from EE's migrations per the port triage, but the
-- ported Go code was not stripped to match and a few CE-bound columns were
-- dropped. See docs/superpowers/specs/2026-09-25-ce-schema-code-parity-design.md.
--
-- Additive and idempotent: safe on fresh installs and on existing 2.x
-- databases, and safe to re-run if the runner fails to record it.

-- hosts: written by UpsertHost (baseline omitted these two columns).
ALTER TABLE hosts
    ADD COLUMN IF NOT EXISTS aliases           JSONB NOT NULL DEFAULT '[]',
    ADD COLUMN IF NOT EXISTS discovery_sources JSONB NOT NULL DEFAULT '[]';

-- asset_health_reports: read and written by SaveAssetHealthReport and every
-- CBOM query. The EE risk engine is EE-only, so CE leaves these at their
-- defaults and adds no risk-score index.
ALTER TABLE asset_health_reports
    ADD COLUMN IF NOT EXISTS risk_score   INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS risk_factors JSONB   NOT NULL DEFAULT '{}';

-- operator_declared_cas / application_metadata: the baseline named these
-- declared_by / declared_at; the store code, the JSON API and EE use added_*.
-- Renames carry existing rows and are guarded so a re-run is a no-op.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = current_schema()
                 AND table_name = 'operator_declared_cas' AND column_name = 'declared_at') THEN
        ALTER TABLE operator_declared_cas RENAME COLUMN declared_at TO added_at;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = current_schema()
                 AND table_name = 'operator_declared_cas' AND column_name = 'declared_by') THEN
        ALTER TABLE operator_declared_cas RENAME COLUMN declared_by TO added_by;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = current_schema()
                 AND table_name = 'application_metadata' AND column_name = 'declared_at') THEN
        ALTER TABLE application_metadata RENAME COLUMN declared_at TO added_at;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = current_schema()
                 AND table_name = 'application_metadata' AND column_name = 'declared_by') THEN
        ALTER TABLE application_metadata RENAME COLUMN declared_by TO added_by;
    END IF;
END
$$;

-- ad_cs_events: written by the Netwrix connector, which ships in CE.
-- Definition copied unchanged from EE migration 007_ad_cs_events.sql.
CREATE TABLE IF NOT EXISTS ad_cs_events (
    id              UUID PRIMARY KEY,

    event_type      TEXT NOT NULL,
    event_timestamp TIMESTAMPTZ NOT NULL,
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    ca_name         TEXT NOT NULL,
    template_name   TEXT,
    requested_by    TEXT,

    serial_number   TEXT NOT NULL,
    issuer_dn       TEXT NOT NULL,
    subject_dn      TEXT,

    source          TEXT NOT NULL DEFAULT 'netwrix',
    raw_event       JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ad_cs_events_event_timestamp ON ad_cs_events (event_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_ad_cs_events_ca_name ON ad_cs_events (ca_name);
CREATE INDEX IF NOT EXISTS idx_ad_cs_events_event_type ON ad_cs_events (event_type);
CREATE INDEX IF NOT EXISTS idx_ad_cs_events_serial_issuer ON ad_cs_events (serial_number, issuer_dn);

-- ssh_keys / crypto_libraries: columns written by UpsertSSHKey and
-- UpsertCryptoLibrary (baseline omitted them).
ALTER TABLE ssh_keys
    ADD COLUMN IF NOT EXISTS owner_user    TEXT    NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS is_authorized BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS is_protected  BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS grants_root   BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE crypto_libraries
    ADD COLUMN IF NOT EXISTS package_manager TEXT NOT NULL DEFAULT '';

-- Sighting tables: the stores read and return created_at.
ALTER TABLE host_ip_sightings
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE asset_ownership_sightings
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- Upsert conflict targets. UpsertSSHKey / UpsertCryptoLibrary use
-- ON CONFLICT (host_id, fingerprint_sha256) and (host_id, library_name, version),
-- which Postgres only accepts with a unique index on exactly those columns; the
-- baseline's wider keys (with file_path / install_path) do not qualify. Their
-- only writers are those two upserts, which could never succeed against the old
-- schema, so these tables hold no rows on any 2.x database and the indexes
-- cannot hit duplicates. The wider keys stay (a narrower unique implies them).
CREATE UNIQUE INDEX IF NOT EXISTS ssh_keys_host_id_fingerprint_sha256_key
    ON ssh_keys (host_id, fingerprint_sha256);
CREATE UNIQUE INDEX IF NOT EXISTS crypto_libraries_host_id_library_name_version_key
    ON crypto_libraries (host_id, library_name, version);

-- CHECK constraints from EE (definitions and names copied unchanged), limited to
-- tables and columns CE has, and skipping asset_ownership_sightings' asset_type
-- check: CE already has its own (deliberately without the EE-only
-- protocol_endpoint value). Added NOT VALID so a stray pre-existing row can
-- never block startup; new and updated rows are still enforced. Guarded by
-- name so a re-run is a no-op.
DO $$
DECLARE
    r record;
BEGIN
    FOR r IN
        SELECT * FROM (VALUES
            ('application_metadata', 'application_metadata_ttl_range',
             'CHECK (data_ttl_years IS NULL OR (data_ttl_years >= 0 AND data_ttl_years <= 100))'),
            ('asset_ownership_sightings', 'aos_confidence_check',
             'CHECK (confidence = ANY (ARRAY[''direct'', ''attested'', ''inferred'', ''observed'']))'),
            ('asset_ownership_sightings', 'aos_source_check',
             'CHECK (source = ANY (ARRAY[''operator_stamp'', ''application_metadata'', ''declared_ca'', ''sighting_agent'', ''git_author'', ''cert_subject'', ''ssh_comment'', ''host_owner'', ''user_identity'', ''entra'', ''csv_import'', ''host_import_cascade'', ''prisma'']))'),
            ('asset_ownership_sightings', 'aos_window_check',
             'CHECK (first_seen <= last_seen)'),
            ('host_ip_sightings', 'host_ip_sightings_confidence_check',
             'CHECK (confidence = ANY (ARRAY[''direct'', ''attested'', ''inferred'', ''observed'']))'),
            ('host_ip_sightings', 'host_ip_sightings_source_check',
             'CHECK (source = ANY (ARRAY[''endpoint'', ''dhcp'', ''zeek_known_hosts'', ''dns_ptr'', ''ddi'', ''ad'']))')
        ) AS v(tbl, cname, def)
    LOOP
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint k
            JOIN pg_class t ON t.oid = k.conrelid
            JOIN pg_namespace s ON s.oid = t.relnamespace
            WHERE s.nspname = current_schema() AND t.relname = r.tbl AND k.conname = r.cname
        ) THEN
            EXECUTE format('ALTER TABLE %I ADD CONSTRAINT %I %s NOT VALID', r.tbl, r.cname, r.def);
        END IF;
    END LOOP;
END
$$;

-- host_ip_sightings: make the table match what the store code assumes.
--   * ip: the code reads it as a string and compares it with text parameters;
--     the baseline used inet ("cannot scan inet into *string",
--     "operator does not exist: inet = text"). host() drops the /32 mask.
--   * host_id: nullable, because sightings for unattributed IPs carry no host.
--   * attribution: never NULL (the store always writes an object).
--   * window check: the baseline named it host_ip_sightings_window_valid; EE and
--     the tests use host_ip_sightings_window_check.
--   * idx_hip_unique: EE's race guard for the select-then-insert upsert; it
--     treats a NULL host as one zero-uuid host so null-host sightings dedupe.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = current_schema()
                 AND table_name = 'host_ip_sightings' AND column_name = 'ip'
                 AND data_type = 'inet') THEN
        ALTER TABLE host_ip_sightings ALTER COLUMN ip TYPE text USING host(ip);
    END IF;

    IF EXISTS (SELECT 1 FROM pg_constraint k
               JOIN pg_class t ON t.oid = k.conrelid
               JOIN pg_namespace s ON s.oid = t.relnamespace
               WHERE s.nspname = current_schema() AND t.relname = 'host_ip_sightings'
                 AND k.conname = 'host_ip_sightings_window_valid')
       AND NOT EXISTS (SELECT 1 FROM pg_constraint k
               JOIN pg_class t ON t.oid = k.conrelid
               JOIN pg_namespace s ON s.oid = t.relnamespace
               WHERE s.nspname = current_schema() AND t.relname = 'host_ip_sightings'
                 AND k.conname = 'host_ip_sightings_window_check') THEN
        ALTER TABLE host_ip_sightings
            RENAME CONSTRAINT host_ip_sightings_window_valid TO host_ip_sightings_window_check;
    END IF;
END
$$;

ALTER TABLE host_ip_sightings ALTER COLUMN host_id DROP NOT NULL;

UPDATE host_ip_sightings SET attribution = '{}'::jsonb WHERE attribution IS NULL;
ALTER TABLE host_ip_sightings
    ALTER COLUMN attribution SET DEFAULT '{}'::jsonb,
    ALTER COLUMN attribution SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_hip_unique
    ON host_ip_sightings (source, ip, COALESCE(host_id, '00000000-0000-0000-0000-000000000000'::uuid));
