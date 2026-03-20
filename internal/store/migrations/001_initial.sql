-- CipherFlag v2 — Initial Schema

CREATE TABLE IF NOT EXISTS certificates (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    fingerprint_sha256       TEXT NOT NULL UNIQUE,
    subject_cn               TEXT NOT NULL DEFAULT '',
    subject_org              TEXT NOT NULL DEFAULT '',
    subject_ou               TEXT NOT NULL DEFAULT '',
    subject_country          TEXT NOT NULL DEFAULT '',
    subject_state            TEXT NOT NULL DEFAULT '',
    subject_locality         TEXT NOT NULL DEFAULT '',
    subject_full             TEXT NOT NULL DEFAULT '',
    issuer_cn                TEXT NOT NULL DEFAULT '',
    issuer_org               TEXT NOT NULL DEFAULT '',
    issuer_ou                TEXT NOT NULL DEFAULT '',
    issuer_country           TEXT NOT NULL DEFAULT '',
    issuer_full              TEXT NOT NULL DEFAULT '',
    serial_number            TEXT NOT NULL DEFAULT '',
    not_before               TIMESTAMPTZ NOT NULL,
    not_after                TIMESTAMPTZ NOT NULL,
    key_algorithm            TEXT NOT NULL DEFAULT 'Unknown',
    key_size_bits            INTEGER NOT NULL DEFAULT 0,
    signature_algorithm      TEXT NOT NULL DEFAULT 'Unknown',
    subject_alt_names        JSONB NOT NULL DEFAULT '[]',
    is_ca                    BOOLEAN NOT NULL DEFAULT FALSE,
    basic_constraints_path_len INTEGER,
    key_usage                JSONB NOT NULL DEFAULT '[]',
    extended_key_usage       JSONB NOT NULL DEFAULT '[]',
    ocsp_responder_urls      JSONB NOT NULL DEFAULT '[]',
    crl_distribution_points  JSONB NOT NULL DEFAULT '[]',
    scts                     JSONB NOT NULL DEFAULT '[]',
    source_discovery         TEXT NOT NULL DEFAULT 'zeek_passive',
    first_seen               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    search_vector            TSVECTOR
);

-- Trigger to auto-update search_vector on insert/update
CREATE OR REPLACE FUNCTION certificates_search_vector_update() RETURNS trigger AS $$
BEGIN
    NEW.search_vector := to_tsvector('english',
        coalesce(NEW.subject_cn, '') || ' ' ||
        coalesce(NEW.subject_org, '') || ' ' ||
        coalesce(NEW.issuer_cn, '') || ' ' ||
        coalesce(NEW.issuer_org, '') || ' ' ||
        coalesce(NEW.fingerprint_sha256, '') || ' ' ||
        coalesce(NEW.serial_number, '')
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_certs_search_vector ON certificates;
CREATE TRIGGER trg_certs_search_vector
    BEFORE INSERT OR UPDATE ON certificates
    FOR EACH ROW EXECUTE FUNCTION certificates_search_vector_update();

CREATE INDEX IF NOT EXISTS idx_certs_fingerprint ON certificates (fingerprint_sha256);
CREATE INDEX IF NOT EXISTS idx_certs_not_after ON certificates (not_after);
CREATE INDEX IF NOT EXISTS idx_certs_issuer_cn ON certificates (issuer_cn);
CREATE INDEX IF NOT EXISTS idx_certs_is_ca ON certificates (is_ca);
CREATE INDEX IF NOT EXISTS idx_certs_source ON certificates (source_discovery);
CREATE INDEX IF NOT EXISTS idx_certs_search ON certificates USING GIN (search_vector);

CREATE TABLE IF NOT EXISTS observations (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cert_fingerprint      TEXT NOT NULL REFERENCES certificates(fingerprint_sha256) ON DELETE CASCADE,
    server_ip             TEXT NOT NULL,
    server_port           INTEGER NOT NULL,
    server_name           TEXT NOT NULL DEFAULT '',
    client_ip             TEXT NOT NULL DEFAULT '',
    negotiated_version    TEXT NOT NULL DEFAULT '',
    negotiated_cipher     TEXT NOT NULL DEFAULT '',
    cipher_strength       TEXT NOT NULL DEFAULT 'Unknown',
    ja3_fingerprint       TEXT NOT NULL DEFAULT '',
    ja3s_fingerprint      TEXT NOT NULL DEFAULT '',
    source                TEXT NOT NULL DEFAULT 'zeek_passive',
    observed_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_obs_cert ON observations (cert_fingerprint);
CREATE INDEX IF NOT EXISTS idx_obs_server ON observations (server_ip, server_port);
CREATE INDEX IF NOT EXISTS idx_obs_time ON observations (observed_at);
CREATE INDEX IF NOT EXISTS idx_obs_version ON observations (negotiated_version);
CREATE INDEX IF NOT EXISTS idx_obs_cipher ON observations (negotiated_cipher);

CREATE TABLE IF NOT EXISTS endpoint_profiles (
    server_ip               TEXT NOT NULL,
    server_port             INTEGER NOT NULL,
    server_name             TEXT NOT NULL DEFAULT '',
    cert_fingerprint        TEXT NOT NULL DEFAULT '',
    min_tls_version         TEXT NOT NULL DEFAULT '',
    max_tls_version         TEXT NOT NULL DEFAULT '',
    cipher_suites           JSONB NOT NULL DEFAULT '[]',
    supports_forward_secrecy BOOLEAN NOT NULL DEFAULT FALSE,
    supports_aead           BOOLEAN NOT NULL DEFAULT FALSE,
    has_weak_ciphers        BOOLEAN NOT NULL DEFAULT FALSE,
    observation_count       INTEGER NOT NULL DEFAULT 0,
    first_seen              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (server_ip, server_port)
);

CREATE TABLE IF NOT EXISTS health_reports (
    cert_fingerprint    TEXT NOT NULL UNIQUE REFERENCES certificates(fingerprint_sha256) ON DELETE CASCADE,
    grade               TEXT NOT NULL DEFAULT 'F',
    score               INTEGER NOT NULL DEFAULT 0,
    findings            JSONB NOT NULL DEFAULT '[]',
    scored_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_health_grade ON health_reports (grade);

CREATE TABLE IF NOT EXISTS ingestion_state (
    source_name TEXT PRIMARY KEY,
    cursor      TEXT NOT NULL DEFAULT '',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Materialized view for dashboard summary (refresh periodically)
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_summary AS
SELECT
    (SELECT COUNT(*) FROM certificates) AS total_certs,
    (SELECT COUNT(*) FROM observations) AS total_observations,
    (SELECT COUNT(*) FROM certificates WHERE not_after < NOW()) AS expired,
    (SELECT COUNT(*) FROM certificates WHERE not_after BETWEEN NOW() AND NOW() + INTERVAL '30 days') AS expiring_30d,
    (SELECT COUNT(*) FROM certificates WHERE not_after BETWEEN NOW() AND NOW() + INTERVAL '90 days') AS expiring_90d;
