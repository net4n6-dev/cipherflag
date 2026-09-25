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
