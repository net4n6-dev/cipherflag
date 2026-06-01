-- v2.1.0_venafi_push.sql
-- Add Venafi push tracking columns to certificates table.
-- Renamed from 004_venafi_push.sql: the old 00N_ prefix sorted BEFORE
-- v2.0_baseline.sql (digits < letters) and the ALTER TABLE failed on a
-- fresh DB because certificates did not yet exist. The v2.1.0_ prefix
-- sorts AFTER the baseline so certificates is created first.

ALTER TABLE certificates ADD COLUMN IF NOT EXISTS venafi_pushed_at TIMESTAMPTZ NULL;
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS venafi_push_failures INT NOT NULL DEFAULT 0;
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS venafi_last_push_attempt TIMESTAMPTZ NULL;
