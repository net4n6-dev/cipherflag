-- v2.2.0_sse_event_triggers.sql
-- Restore the SSE event stream's publish side: pg_notify triggers on the asset
-- tables. The Go listener (internal/sse) LISTENs on 'cipherflag_events' and fans
-- notifications to connected EventSource clients. Asset events only
-- (certificates/ssh_keys/crypto_libraries -> asset.discovered, asset_health_reports
-- -> asset.scored); scan/briefing/external-source triggers are intentionally omitted.

-- cf_notify_event takes JSON (trigger call sites pass json_build_object(...) which
-- is json, not jsonb — no implicit cast exists).
DROP FUNCTION IF EXISTS cf_notify_event(TEXT, JSONB);
CREATE OR REPLACE FUNCTION cf_notify_event(event_type TEXT, payload JSON) RETURNS void AS $$
BEGIN
  PERFORM pg_notify('cipherflag_events', json_build_object(
    'type', event_type,
    'data', payload,
    'timestamp', NOW()
  )::text);
END $$ LANGUAGE plpgsql;

-- Certificate insert -> asset.discovered (CE column is source_discovery, not source)
CREATE OR REPLACE FUNCTION notify_cert_discovered() RETURNS trigger AS $$
BEGIN
  PERFORM cf_notify_event('asset.discovered', json_build_object(
    'asset_type', 'certificate',
    'asset_id', NEW.fingerprint_sha256,
    'source', NEW.source_discovery
  ));
  RETURN NEW;
END $$ LANGUAGE plpgsql;
CREATE OR REPLACE TRIGGER cert_discovered_trigger
  AFTER INSERT ON certificates
  FOR EACH ROW EXECUTE FUNCTION notify_cert_discovered();

-- SSH key insert -> asset.discovered
CREATE OR REPLACE FUNCTION notify_ssh_key_discovered() RETURNS trigger AS $$
BEGIN
  PERFORM cf_notify_event('asset.discovered', json_build_object(
    'asset_type', 'ssh_key',
    'asset_id', NEW.id,
    'host_id', NEW.host_id,
    'source', NEW.source
  ));
  RETURN NEW;
END $$ LANGUAGE plpgsql;
CREATE OR REPLACE TRIGGER ssh_key_discovered_trigger
  AFTER INSERT ON ssh_keys
  FOR EACH ROW EXECUTE FUNCTION notify_ssh_key_discovered();

-- Crypto library insert -> asset.discovered
CREATE OR REPLACE FUNCTION notify_library_discovered() RETURNS trigger AS $$
BEGIN
  PERFORM cf_notify_event('asset.discovered', json_build_object(
    'asset_type', 'crypto_library',
    'asset_id', NEW.id,
    'host_id', NEW.host_id,
    'source', NEW.source
  ));
  RETURN NEW;
END $$ LANGUAGE plpgsql;
CREATE OR REPLACE TRIGGER library_discovered_trigger
  AFTER INSERT ON crypto_libraries
  FOR EACH ROW EXECUTE FUNCTION notify_library_discovered();

-- Asset health report upsert -> asset.scored
-- asset_health_reports uses 'score' (not 'risk_score'); payload key kept as
-- 'risk_score' for API stability but mapped from the actual 'score' column.
CREATE OR REPLACE FUNCTION notify_asset_scored() RETURNS trigger AS $$
BEGIN
  PERFORM cf_notify_event('asset.scored', json_build_object(
    'asset_type', NEW.asset_type,
    'asset_id', NEW.asset_id,
    'grade', NEW.grade,
    'risk_score', NEW.score,
    'pqc_status', NEW.pqc_status
  ));
  RETURN NEW;
END $$ LANGUAGE plpgsql;
CREATE OR REPLACE TRIGGER asset_scored_trigger
  AFTER INSERT OR UPDATE ON asset_health_reports
  FOR EACH ROW EXECUTE FUNCTION notify_asset_scored();
