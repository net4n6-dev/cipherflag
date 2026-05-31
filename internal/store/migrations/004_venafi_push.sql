-- 004_venafi_push.sql
-- Add Venafi push tracking columns to certificates table.

ALTER TABLE certificates ADD COLUMN IF NOT EXISTS venafi_pushed_at TIMESTAMPTZ NULL;
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS venafi_push_failures INT NOT NULL DEFAULT 0;
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS venafi_last_push_attempt TIMESTAMPTZ NULL;
