-- CipherFlag CE v2.0.0 — baseline schema
-- Generated 2026-05-26 from EE migrations per docs/superpowers/ce-port/triage-migrations.md.
--
-- This single migration REPLACES the v1.x incremental migrations 001-005
-- with the post-Phase-1 schema baked-in. Existing CE v1.x users must
-- reinitialize their database — no automated v1→v2 data migration is
-- provided. See CHANGELOG.md v2.0.0 §"Compatibility".
--
-- Excluded from CE Phase 1 (EE-only or Phase 2):
--  • protocol_observations / protocol_endpoints (Layer 4.1c)
--  • host_dependency_edges / host_blast_radius / ssh_edge_details /
--    shared_cert_edge_details / app_tag_edge_details / pki_edge_details /
--    pki_trusted_by_edge_details (Layer 4.4 risk engine SP-1..1.6)
--  • risk_score + risk_factors columns on asset_health_reports
--  • rank_review_observations (Layer 4.4 SP-3/4)
--  • cert_issuance link table (kept AKI/SKI columns on certificates)
--  • sweep_watermarks (Layer 4.4 sweep helper)
--  • ai_usage_ledger + ai_guardrail_violations (Layer 6.1d AI tier)
--  • briefing_cache (Layer 8)
--  • application_posture_snapshots (Layer 8)
--  • event_notify triggers (Layer 8 SSE)
--  • teams (Layer 8 multi-tenant)
--  • pcap_jobs (legacy CE-v1; superseded)
--  • ad_cs_events (Netwrix)
--  • Venafi push columns on certificates (Layer 5.4)
--  • external_sources + external_source_scan_history (Phase 2 — CT/AWS)
--  • pqc_migration_policy + pqc_migration_snapshots (Layer 4-G EE)
--
-- Kept (not excluded) because osquery webhook ingest uses these as the
-- raw TLS-observation storage layer:
--  • observations + endpoint_profiles (legacy precursors to Layer 4.1c).
--    Layer 4.1c protocol-endpoint *scoring* on top of them remains
--    EE-only; CE stores the observations but does not score them as
--    crypto_protocol assets.

-- ──────────────────────────────────────────────────────────────────────
-- Layer 0 — asset inventory
-- ──────────────────────────────────────────────────────────────────────

-- certificates (from 001 + 003 raw_pem + 006 host fields + 018 trigger
-- + 021 application_tags + 040 AKI/SKI columns + 042 spki_fingerprint).
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
    search_vector            TSVECTOR,
    raw_pem                  TEXT NOT NULL DEFAULT '',
    -- host attribution columns (from 006)
    discovered_on_host       UUID,
    file_path                TEXT NOT NULL DEFAULT '',
    store_type               TEXT NOT NULL DEFAULT 'network',
    discovery_status         TEXT NOT NULL DEFAULT 'active',
    -- application metadata (from 021)
    application_tags         TEXT[] NOT NULL DEFAULT '{}',
    -- PKI metadata (from 040; link table dropped, columns kept)
    authority_key_id         BYTEA,
    subject_key_id           BYTEA,
    issuer_fingerprint_sha256 TEXT,
    -- SPKI fingerprint (from 042; used by certfiles scanner)
    spki_fingerprint_sha256  TEXT
);

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
CREATE INDEX IF NOT EXISTS idx_certs_aki ON certificates (authority_key_id) WHERE authority_key_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_certs_ski ON certificates (subject_key_id) WHERE subject_key_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_certs_spki_fingerprint ON certificates (spki_fingerprint_sha256) WHERE spki_fingerprint_sha256 IS NOT NULL;

-- observations (from 001 — raw TLS-handshake records keyed by cert
-- fingerprint). Populated by osquery webhook ingest and any future
-- passive sources. CE keeps the storage layer; Layer 4.1c protocol-
-- endpoint scoring on top of these rows is EE-only.
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

-- endpoint_profiles (from 001 — per-(server_ip, server_port) rollup of
-- TLS posture, derived from the observations stream). CE keeps this
-- legacy storage; protocol-endpoint scoring is EE-only.
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

-- health_reports (from 001 — legacy cert-only table; CryptoStore still uses it)
CREATE TABLE IF NOT EXISTS health_reports (
    cert_fingerprint    TEXT NOT NULL UNIQUE REFERENCES certificates(fingerprint_sha256) ON DELETE CASCADE,
    grade               TEXT NOT NULL DEFAULT 'F',
    score               INTEGER NOT NULL DEFAULT 0,
    findings            JSONB NOT NULL DEFAULT '[]',
    scored_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_health_grade ON health_reports (grade);

-- ingestion_state (from 001)
CREATE TABLE IF NOT EXISTS ingestion_state (
    source_name TEXT PRIMARY KEY,
    cursor      TEXT NOT NULL DEFAULT '',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- users (from 005 — bedrock auth)
CREATE TABLE IF NOT EXISTS users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    display_name    TEXT NOT NULL DEFAULT '',
    role            TEXT NOT NULL DEFAULT 'viewer' CHECK (role IN ('admin', 'editor', 'viewer')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);

-- hosts (from 006 + 021)
CREATE TABLE IF NOT EXISTS hosts (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    canonical_hostname  TEXT NOT NULL DEFAULT '',
    ip_addresses        JSONB NOT NULL DEFAULT '[]',
    os_family           TEXT NOT NULL DEFAULT '',
    os_version          TEXT NOT NULL DEFAULT '',
    host_type           TEXT NOT NULL DEFAULT 'unknown',
    discovery_status    TEXT NOT NULL DEFAULT 'active',
    first_seen          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    application_tags    TEXT[] NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts USING GIN (ip_addresses);
CREATE INDEX IF NOT EXISTS idx_hosts_canonical ON hosts (canonical_hostname);
CREATE INDEX IF NOT EXISTS idx_hosts_type ON hosts (host_type);

-- host_identifiers (from 006)
CREATE TABLE IF NOT EXISTS host_identifiers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    source          TEXT NOT NULL,
    source_host_id  TEXT NOT NULL,
    UNIQUE(source, source_host_id)
);
CREATE INDEX IF NOT EXISTS idx_host_ident_host ON host_identifiers (host_id);

-- back-wire cert -> host FK (was deferred in 006 due to host-existence)
ALTER TABLE certificates ADD CONSTRAINT fk_certs_discovered_on_host
    FOREIGN KEY (discovered_on_host) REFERENCES hosts(id);

-- ssh_keys (from 006 + 018 trigger + 021 tags + 027 comment)
CREATE TABLE IF NOT EXISTS ssh_keys (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id             UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    key_type            TEXT NOT NULL,
    key_size_bits       INTEGER NOT NULL DEFAULT 0,
    fingerprint_sha256  TEXT NOT NULL,
    file_path           TEXT NOT NULL DEFAULT '',
    is_authorized_keys  BOOLEAN NOT NULL DEFAULT FALSE,
    is_private_key      BOOLEAN NOT NULL DEFAULT FALSE,
    has_passphrase      BOOLEAN NOT NULL DEFAULT FALSE,
    discovery_status    TEXT NOT NULL DEFAULT 'active',
    source              TEXT NOT NULL DEFAULT '',
    first_seen          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    application_tags    TEXT[] NOT NULL DEFAULT '{}',
    comment             TEXT NOT NULL DEFAULT '',
    search_vector       TSVECTOR,
    UNIQUE(host_id, fingerprint_sha256, file_path)
);
CREATE INDEX IF NOT EXISTS idx_ssh_keys_host ON ssh_keys (host_id);
CREATE INDEX IF NOT EXISTS idx_ssh_keys_status ON ssh_keys (discovery_status);

CREATE OR REPLACE FUNCTION ssh_keys_search_vector_update() RETURNS trigger AS $$
BEGIN
    NEW.search_vector := to_tsvector('english',
        coalesce(NEW.key_type, '') || ' ' ||
        coalesce(NEW.fingerprint_sha256, '') || ' ' ||
        coalesce(NEW.file_path, '') || ' ' ||
        coalesce(NEW.comment, '') || ' ' ||
        coalesce(NEW.source, '')
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_ssh_keys_search_vector ON ssh_keys;
CREATE TRIGGER trg_ssh_keys_search_vector
    BEFORE INSERT OR UPDATE ON ssh_keys
    FOR EACH ROW EXECUTE FUNCTION ssh_keys_search_vector_update();

CREATE INDEX IF NOT EXISTS idx_ssh_keys_search ON ssh_keys USING GIN (search_vector);

-- crypto_libraries (from 006 + 018 trigger + 021 tags)
CREATE TABLE IF NOT EXISTS crypto_libraries (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id             UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    library_name        TEXT NOT NULL,
    version             TEXT NOT NULL DEFAULT '',
    package_name        TEXT NOT NULL DEFAULT '',
    install_path        TEXT NOT NULL DEFAULT '',
    source              TEXT NOT NULL DEFAULT '',
    pqc_capable         BOOLEAN NOT NULL DEFAULT FALSE,
    discovery_status    TEXT NOT NULL DEFAULT 'active',
    first_seen          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    application_tags    TEXT[] NOT NULL DEFAULT '{}',
    search_vector       TSVECTOR,
    UNIQUE(host_id, library_name, version, install_path)
);
CREATE INDEX IF NOT EXISTS idx_crypto_libs_host ON crypto_libraries (host_id);
CREATE INDEX IF NOT EXISTS idx_crypto_libs_name ON crypto_libraries (library_name);
CREATE INDEX IF NOT EXISTS idx_crypto_libs_status ON crypto_libraries (discovery_status);

CREATE OR REPLACE FUNCTION crypto_libraries_search_vector_update() RETURNS trigger AS $$
BEGIN
    NEW.search_vector := to_tsvector('english',
        coalesce(NEW.library_name, '') || ' ' ||
        coalesce(NEW.version, '') || ' ' ||
        coalesce(NEW.package_name, '') || ' ' ||
        coalesce(NEW.install_path, '') || ' ' ||
        coalesce(NEW.source, '')
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_crypto_libs_search_vector ON crypto_libraries;
CREATE TRIGGER trg_crypto_libs_search_vector
    BEFORE INSERT OR UPDATE ON crypto_libraries
    FOR EACH ROW EXECUTE FUNCTION crypto_libraries_search_vector_update();

CREATE INDEX IF NOT EXISTS idx_crypto_libs_search ON crypto_libraries USING GIN (search_vector);

-- crypto_library_cves (from 006; populated by 010 seed)
CREATE TABLE IF NOT EXISTS crypto_library_cves (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    library_name    TEXT NOT NULL,
    version_range   TEXT NOT NULL,
    cve_id          TEXT NOT NULL,
    severity        TEXT NOT NULL DEFAULT 'unknown',
    description     TEXT NOT NULL DEFAULT '',
    UNIQUE(library_name, cve_id)
);

-- crypto_configs (from 006 + 018 trigger + 021 tags)
CREATE TABLE IF NOT EXISTS crypto_configs (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id             UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    config_type         TEXT NOT NULL,
    file_path           TEXT NOT NULL,
    settings            JSONB NOT NULL DEFAULT '{}',
    findings            JSONB NOT NULL DEFAULT '[]',
    source              TEXT NOT NULL DEFAULT '',
    discovery_status    TEXT NOT NULL DEFAULT 'active',
    first_seen          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    application_tags    TEXT[] NOT NULL DEFAULT '{}',
    search_vector       TSVECTOR,
    UNIQUE(host_id, file_path)
);
CREATE INDEX IF NOT EXISTS idx_crypto_configs_host ON crypto_configs (host_id);
CREATE INDEX IF NOT EXISTS idx_crypto_configs_type ON crypto_configs (config_type);

CREATE OR REPLACE FUNCTION crypto_configs_search_vector_update() RETURNS trigger AS $$
BEGIN
    NEW.search_vector := to_tsvector('english',
        coalesce(NEW.config_type, '') || ' ' ||
        coalesce(NEW.file_path, '') || ' ' ||
        coalesce(NEW.source, '')
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_crypto_configs_search_vector ON crypto_configs;
CREATE TRIGGER trg_crypto_configs_search_vector
    BEFORE INSERT OR UPDATE ON crypto_configs
    FOR EACH ROW EXECUTE FUNCTION crypto_configs_search_vector_update();

CREATE INDEX IF NOT EXISTS idx_crypto_configs_search ON crypto_configs USING GIN (search_vector);

-- asset_health_reports (from 006 + 008 rule_engine_version partial index;
-- 009 risk_score/risk_factors columns EXCLUDED as EE-only)
CREATE TABLE IF NOT EXISTS asset_health_reports (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_type          TEXT NOT NULL,
    asset_id            TEXT NOT NULL,
    grade               TEXT NOT NULL DEFAULT '',
    score               INTEGER NOT NULL DEFAULT 0,
    findings            JSONB NOT NULL DEFAULT '[]',
    pqc_status          TEXT NOT NULL DEFAULT 'unknown',
    compliance          JSONB NOT NULL DEFAULT '{}',
    scored_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rule_engine_version INTEGER NOT NULL DEFAULT 0,
    UNIQUE(asset_type, asset_id)
);
CREATE INDEX IF NOT EXISTS idx_asset_health_type ON asset_health_reports (asset_type);
CREATE INDEX IF NOT EXISTS idx_asset_health_grade ON asset_health_reports (grade);
-- Stale-sweep partial index. Predicate matches CurrentRuleEngineVersion
-- (currently 3 per migration 010). Future rule-version bumps follow the
-- same DROP-INDEX/CREATE-INDEX pattern as in EE.
CREATE INDEX IF NOT EXISTS idx_asset_health_reports_stale
    ON asset_health_reports (scored_at)
    WHERE rule_engine_version < 3;

-- asset_provenance (from 006; external_source_id from 032 EXCLUDED Phase 2)
CREATE TABLE IF NOT EXISTS asset_provenance (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_type  TEXT NOT NULL,
    asset_id    TEXT NOT NULL,
    source      TEXT NOT NULL,
    host_id     UUID REFERENCES hosts(id) ON DELETE SET NULL,
    file_path   TEXT NOT NULL DEFAULT '',
    store_type  TEXT NOT NULL DEFAULT '',
    raw_metadata JSONB NOT NULL DEFAULT '{}',
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- CE-flavor: external_source_id column added by EE Phase 2 (migration 032);
    -- column kept nullable so the provenance.go code (which reads/writes it
    -- unconditionally) doesn't need a CE-side branch. NULL when CE.
    external_source_id UUID
);
CREATE INDEX IF NOT EXISTS idx_provenance_asset ON asset_provenance (asset_type, asset_id);
CREATE INDEX IF NOT EXISTS idx_provenance_source ON asset_provenance (source);
CREATE UNIQUE INDEX IF NOT EXISTS idx_provenance_unique
ON asset_provenance (asset_type, asset_id, source, COALESCE(host_id, '00000000-0000-0000-0000-000000000000'));

-- agent_tokens (from 006)
CREATE TABLE IF NOT EXISTS agent_tokens (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    token_prefix TEXT NOT NULL,
    created_by   UUID NOT NULL REFERENCES users(id),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_agent_tokens_hash ON agent_tokens (token_hash);

-- host_ip_sightings (from 024 — Layer 0 cert↔host attribution)
CREATE TABLE IF NOT EXISTS host_ip_sightings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    ip              INET NOT NULL,
    first_seen      TIMESTAMPTZ NOT NULL,
    last_seen       TIMESTAMPTZ NOT NULL,
    source          TEXT NOT NULL,
    confidence      TEXT NOT NULL DEFAULT 'direct',
    attribution     JSONB,
    CONSTRAINT host_ip_sightings_window_valid CHECK (first_seen <= last_seen)
);
CREATE INDEX IF NOT EXISTS idx_host_ip_sightings_host ON host_ip_sightings (host_id);
CREATE INDEX IF NOT EXISTS idx_host_ip_sightings_ip ON host_ip_sightings (ip);
CREATE INDEX IF NOT EXISTS idx_host_ip_sightings_last_seen ON host_ip_sightings (last_seen);

-- operator_declared_cas (from 025 + 045 holder_host_id column)
CREATE TABLE IF NOT EXISTS operator_declared_cas (
    fingerprint_sha256  TEXT PRIMARY KEY,
    subject_cn          TEXT NOT NULL DEFAULT '',
    declared_by         UUID REFERENCES users(id),
    declared_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    note                TEXT NOT NULL DEFAULT '',
    owner_team          TEXT NOT NULL DEFAULT '',
    holder_host_id      UUID REFERENCES hosts(id) ON DELETE SET NULL
);

-- application_metadata (from 026)
CREATE TABLE IF NOT EXISTS application_metadata (
    tag                     TEXT PRIMARY KEY,
    data_ttl_years          INTEGER,
    data_sensitive_until    DATE,
    owner_team              TEXT NOT NULL DEFAULT '',
    note                    TEXT NOT NULL DEFAULT '',
    declared_by             UUID REFERENCES users(id),
    declared_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- asset_ownership_sightings (from 028)
CREATE TABLE IF NOT EXISTS asset_ownership_sightings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_type      TEXT NOT NULL CHECK (asset_type IN
        ('certificate', 'ssh_key', 'crypto_library', 'crypto_config',
         'host', 'repository')),
    asset_id        TEXT NOT NULL,
    source          TEXT NOT NULL,
    team            TEXT NOT NULL,
    confidence      TEXT NOT NULL DEFAULT 'inferred',
    named_owner     TEXT NOT NULL DEFAULT '',
    business_svc    TEXT NOT NULL DEFAULT '',
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    evidence        JSONB NOT NULL DEFAULT '{}',
    UNIQUE(asset_type, asset_id, source, team)
);
CREATE INDEX IF NOT EXISTS idx_ownership_asset ON asset_ownership_sightings (asset_type, asset_id);
CREATE INDEX IF NOT EXISTS idx_ownership_team ON asset_ownership_sightings (team);
CREATE INDEX IF NOT EXISTS idx_ownership_source ON asset_ownership_sightings (source);

-- ──────────────────────────────────────────────────────────────────────
-- Layer 4.1b — CVE seed data (from 010)
-- ──────────────────────────────────────────────────────────────────────

-- CVE seed data. Idempotent: ON CONFLICT (library_name, cve_id) DO NOTHING.

-- ── OpenSSL ──────────────────────────────────────────────────────────────────
INSERT INTO crypto_library_cves (library_name, version_range, cve_id, severity, description)
VALUES
  ('openssl', '>=1.0.1 <1.0.1g',  'CVE-2014-0160', 'Critical', 'Heartbleed: TLS heartbeat overread exposes server memory'),
  ('openssl', '>=1.0.0 <1.0.2h',  'CVE-2014-0224', 'High',     'CCS injection: ChangeCipherSpec allows MitM on TLS sessions'),
  ('openssl', '>=1.0.1 <1.0.2g',  'CVE-2016-0800', 'Critical', 'DROWN: SSLv2 export cipher enables cross-protocol decryption attack'),
  ('openssl', '>=1.0.2 <3.0.2',   'CVE-2022-0778', 'High',     'Infinite loop in BN_mod_sqrt with crafted EC certificate'),
  ('openssl', '>=3.0.0 <3.0.7',   'CVE-2022-3602', 'Critical', 'Punycode decoder stack buffer overflow in X.509 email SAN'),
  ('openssl', '>=3.0.0 <3.0.7',   'CVE-2022-3786', 'Critical', 'Punycode wildcard email buffer overflow in X.509 certificate'),
  ('openssl', '>=1.0.2 <3.0.8',   'CVE-2023-0286', 'High',     'Type confusion in X.400 address GeneralName allows read or DoS'),
  ('openssl', '>=1.1.1 <3.0.13',  'CVE-2023-5678', 'Medium',   'Excessive DH key generation time with large Q causes DoS'),
  ('openssl', '>=1.0.2 <3.0.13',  'CVE-2024-0727', 'Medium',   'Null pointer deref processing malformed PKCS12 files'),
  ('openssl', '>=1.0.2 <3.0.14',  'CVE-2024-5535', 'Medium',   'SSL_select_next_proto buffer overread with empty client list')
ON CONFLICT (library_name, cve_id) DO NOTHING;

-- ── GnuTLS ───────────────────────────────────────────────────────────────────
INSERT INTO crypto_library_cves (library_name, version_range, cve_id, severity, description)
VALUES
  ('gnutls', '>=3.3.0 <3.4.8',  'CVE-2015-7575', 'Medium', 'SLOTH: MD5 signatures accepted in ServerKeyExchange'),
  ('gnutls', '>=3.6.0 <3.6.14', 'CVE-2020-13777', 'High',  'TLS 1.3 session ticket key not randomised on handshake'),
  ('gnutls', '>=3.6.0 <3.7.1',  'CVE-2021-20232', 'High',  'Use-after-free in client hello key_share extension'),
  ('gnutls', '>=3.6.0 <3.8.1',  'CVE-2023-5981', 'Medium', 'RSA-PSK: incomplete fix for timing oracle'),
  ('gnutls', '>=3.6.0 <3.8.3',  'CVE-2024-0553', 'Medium', 'RSA-PSK: incomplete fix for CVE-2023-5981 timing oracle')
ON CONFLICT (library_name, cve_id) DO NOTHING;

-- ── wolfSSL ──────────────────────────────────────────────────────────────────
INSERT INTO crypto_library_cves (library_name, version_range, cve_id, severity, description)
VALUES
  ('wolfssl', '>=5.0.0 <5.5.3', 'CVE-2022-42905', 'Critical', 'Heap buffer overread in DTLS decode_ServerHello'),
  ('wolfssl', '>=5.0.0 <5.6.4', 'CVE-2023-3724',  'High',     'Buffer overread via crafted DH public key'),
  ('wolfssl', '>=5.0.0 <5.6.6', 'CVE-2023-6935',  'High',     'RSA timing side-channel in private key operations'),
  ('wolfssl', '>=5.0.0 <5.7.0', 'CVE-2024-1544',  'Medium',   'ECC key generation timing leak via scalar blinding')
ON CONFLICT (library_name, cve_id) DO NOTHING;

-- ── BouncyCastle ─────────────────────────────────────────────────────────────
INSERT INTO crypto_library_cves (library_name, version_range, cve_id, severity, description)
VALUES
  ('bouncycastle', '>=1.60 <1.73', 'CVE-2023-33201', 'Medium', 'LDAP injection via unescaped X.500 distinguished name'),
  ('bouncycastle', '>=1.60 <1.78', 'CVE-2024-29857', 'High',   'EC point decompression with invalid curve causes DoS'),
  ('bouncycastle', '>=1.60 <1.78', 'CVE-2024-30171', 'High',   'RSA PKCS#1v1.5 decrypt timing oracle in TLS handshake'),
  ('bouncycastle', '>=1.60 <1.78', 'CVE-2024-30172', 'Medium', 'Infinite loop in Ed448 signature verification')
ON CONFLICT (library_name, cve_id) DO NOTHING;

-- ── NSS ──────────────────────────────────────────────────────────────────────
INSERT INTO crypto_library_cves (library_name, version_range, cve_id, severity, description)
VALUES
  ('nss', '>=3.40 <3.89', 'CVE-2023-0767', 'Critical', 'Arbitrary memory write via crafted PKCS 12 SafeContents'),
  ('nss', '>=3.60 <3.93', 'CVE-2023-4421', 'Medium',   'Timing side-channel in RSA decryption via cache analysis'),
  ('nss', '>=3.60 <3.95', 'CVE-2023-6135', 'Medium',   'Side-channel in ECDH key agreement for Brainpool curves')
ON CONFLICT (library_name, cve_id) DO NOTHING;

-- ── LibreSSL ─────────────────────────────────────────────────────────────────
INSERT INTO crypto_library_cves (library_name, version_range, cve_id, severity, description)
VALUES
  ('libressl', '>=3.6.0 <3.7.3', 'CVE-2022-48437', 'Medium', 'X.509 GeneralName processing out-of-bounds read'),
  ('libressl', '>=3.7.0 <3.7.3', 'CVE-2023-35784', 'Medium', 'Double free in PKCS7 parsing under certain configurations')
ON CONFLICT (library_name, cve_id) DO NOTHING;

-- ── mbedTLS ──────────────────────────────────────────────────────────────────
INSERT INTO crypto_library_cves (library_name, version_range, cve_id, severity, description)
VALUES
  ('mbedtls', '>=2.0.0 <2.28.1', 'CVE-2021-44732', 'Critical', 'Heap buffer overflow in TLS 1.3 certificate chain'),
  ('mbedtls', '>=2.0.0 <2.28.4', 'CVE-2022-35409', 'Critical', 'Buffer overflow in DTLS ClientHello cookie parsing'),
  ('mbedtls', '>=2.28.0 <2.28.8','CVE-2023-43615', 'Medium',   'Timing attack in ARIA-CTR mode via cache access pattern'),
  ('mbedtls', '>=3.0.0 <3.6.1',  'CVE-2024-23775', 'High',     'Integer overflow in DTLS size calculation leads to overwrite')
ON CONFLICT (library_name, cve_id) DO NOTHING;

-- ── libgcrypt ────────────────────────────────────────────────────────────────
INSERT INTO crypto_library_cves (library_name, version_range, cve_id, severity, description)
VALUES
  ('libgcrypt', '>=1.7.0 <1.7.9',  'CVE-2017-0379', 'High',   'Elgamal side-channel leaks private key via cache timing'),
  ('libgcrypt', '>=1.8.0 <1.8.8',  'CVE-2021-33560', 'High',  'Elgamal encryption side-channel in mpi_powm operations'),
  ('libgcrypt', '>=1.8.0 <1.10.3', 'CVE-2024-2236', 'Medium', 'Timing attack in RSA decryption via libgcrypt padding')
ON CONFLICT (library_name, cve_id) DO NOTHING;

-- ── Nettle ───────────────────────────────────────────────────────────────────
INSERT INTO crypto_library_cves (library_name, version_range, cve_id, severity, description)
VALUES
  ('nettle', '>=3.0.0 <3.7.3', 'CVE-2021-3580',  'High', 'RSA decryption timing side-channel via mpz_powm'),
  ('nettle', '>=3.0.0 <3.7.3', 'CVE-2021-20305', 'High', 'Out-of-bounds read in ecc_ecdsa_sign_itch via short input')
ON CONFLICT (library_name, cve_id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────────────
-- Layer 6.1 — Git repo scanner (deterministic only in CE)
-- ──────────────────────────────────────────────────────────────────────

-- ==== from 012_repositories_and_lineage.sql + 014 + 015 ====
-- 012_repositories_and_lineage.sql
-- Layer 6.1a: Asset model (Path A — lightweight).
-- Adds two tables and registers 'repository' as a new asset_type value in
-- the existing polymorphism used by asset_health_reports and asset_provenance.
-- No existing table is altered.

-- Repositories -----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS repositories (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- provider_id FK is added in migration 014 (after providers exists in 013).
    provider_id         UUID NOT NULL,
    url                 TEXT NOT NULL,
    default_branch      TEXT NOT NULL DEFAULT 'main',
    schedule_cron       TEXT,
    default_scan_mode   TEXT NOT NULL DEFAULT 'enrichment',
    tags                JSONB NOT NULL DEFAULT '{}',
    auth_secret_ref     TEXT,
    last_scanned_sha    TEXT,
    last_scan_at        TIMESTAMPTZ,
    first_seen          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (provider_id, url)
);
CREATE INDEX IF NOT EXISTS idx_repos_provider ON repositories (provider_id);
CREATE INDEX IF NOT EXISTS idx_repos_tags     ON repositories USING GIN (tags);

-- Lineage Links ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS lineage_links (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    from_asset_type     TEXT NOT NULL,
    from_asset_id       TEXT NOT NULL,
    to_asset_type       TEXT NOT NULL,
    to_asset_id         TEXT NOT NULL,
    link_type           TEXT NOT NULL,
    confidence          NUMERIC(3,2) NOT NULL DEFAULT 1.0,
    evidence            JSONB NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (from_asset_type, from_asset_id, to_asset_type, to_asset_id, link_type)
);
CREATE INDEX IF NOT EXISTS idx_lineage_from ON lineage_links (from_asset_type, from_asset_id);
CREATE INDEX IF NOT EXISTS idx_lineage_to   ON lineage_links (to_asset_type,   to_asset_id);

-- (014 FK + 015 last_scheduled rolled in below after providers table)

-- ==== from 013_scanner_operational.sql (CE subset — drops ai_usage_ledger + ai_guardrail_violations) ====

-- 013_scanner_operational.sql
-- Layer 6.1b-1: Scanner operational tables.
-- providers, scan_jobs, repo_scan_cache, ai_usage_ledger, ai_guardrail_violations.
-- Only `providers` is wired to Go code in this sub-plan; the others exist
-- as empty tables and become usable in 6.1b-2 (scan_jobs, repo_scan_cache)
-- and 6.1d (ai_usage_ledger, ai_guardrail_violations).

-- Providers ------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS providers (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind                TEXT NOT NULL,       -- 'github' | 'github_enterprise' | 'gitlab' | 'gitlab_self_managed' | 'bitbucket' | 'bitbucket_server'
    base_url            TEXT NOT NULL,       -- e.g. 'https://github.com' or self-hosted URL
    auth_secret_ref     TEXT NOT NULL,       -- opaque secret reference string; resolved at clone time (6.1b-2)
    display_name        TEXT NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (kind, base_url)
);

-- Scan Jobs (queue) ----------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_jobs (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repo_id             UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    scan_mode           TEXT NOT NULL,                -- 'deterministic_only' | 'triage' | 'enrichment' | 'deep'
    trigger             TEXT NOT NULL,                -- 'manual' | 'scheduled'
    branch_ref          TEXT NOT NULL DEFAULT '',
    status              TEXT NOT NULL DEFAULT 'queued', -- 'queued' | 'running' | 'completed' | 'failed' | 'cancelled'
    worker_id           TEXT NOT NULL DEFAULT '',
    started_at          TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,
    summary_json        JSONB NOT NULL DEFAULT '{}',
    llm_tokens_spent    INTEGER NOT NULL DEFAULT 0,
    llm_cost_usd        NUMERIC(10,4) NOT NULL DEFAULT 0,
    findings_count      INTEGER NOT NULL DEFAULT 0,
    error_text          TEXT NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- Partial index powers the SKIP LOCKED claim loop (6.1b-2).
CREATE INDEX IF NOT EXISTS idx_scan_jobs_queued ON scan_jobs (created_at)
    WHERE status = 'queued';
CREATE INDEX IF NOT EXISTS idx_scan_jobs_repo   ON scan_jobs (repo_id);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs (status);

-- Repo Scan Cache ------------------------------------------------------------
-- Key: (blob_sha, rule_version, prompt_content_hash, scan_mode).
-- prompt_content_hash = SHA-256 of prompt body per spec §7; '' when mode='deterministic_only'.
CREATE TABLE IF NOT EXISTS repo_scan_cache (
    blob_sha            BYTEA NOT NULL,
    rule_version        TEXT NOT NULL,
    prompt_content_hash TEXT NOT NULL DEFAULT '',
    scan_mode           TEXT NOT NULL,
    findings_json       JSONB NOT NULL,
    scanned_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    token_cost          INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (blob_sha, rule_version, prompt_content_hash, scan_mode)
);
CREATE INDEX IF NOT EXISTS idx_repo_scan_cache_scanned_at ON repo_scan_cache (scanned_at);

-- CE-flavor: ai_usage_ledger + ai_guardrail_violations tables are
-- EE-only (Layer 6.1d AI tier). Excluded from the baseline.

-- ==== from 014_repositories_fk.sql ====
-- 014_repositories_fk.sql
-- Layer 6.1b-1: Back-wire the FK from repositories.provider_id to providers.id.
-- Migration 012 created repositories with provider_id NOT NULL but no FK
-- (providers did not exist yet). Migration 013 created providers. Now the
-- FK can be added safely.
--
-- Idempotent: uses an existence check via DO-block. The check is scoped
-- to current_schema() so per-schema test isolation doesn't see sibling
-- schemas' constraints and wrongly skip the CREATE here.

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'fk_repositories_provider'
          AND table_name      = 'repositories'
          AND table_schema    = current_schema()
    ) THEN
        ALTER TABLE repositories
            ADD CONSTRAINT fk_repositories_provider
            FOREIGN KEY (provider_id) REFERENCES providers(id) ON DELETE CASCADE;
    END IF;
END $$;

-- ==== from 015_repository_last_scheduled.sql ====
-- 015_repository_last_scheduled.sql
-- Layer 6.1b-4: scheduler needs a persistent "last fired" cursor per repo so
-- a cipherflag restart doesn't double-fire schedules.

ALTER TABLE repositories
    ADD COLUMN IF NOT EXISTS last_scheduled_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_repos_scheduled
    ON repositories (last_scheduled_at)
    WHERE schedule_cron IS NOT NULL AND schedule_cron <> '';

-- ==== from 016_container_registry_support.sql ====
-- 016_container_registry_support.sql
-- Layer 6.2a: scan-job retry state + repo_scan_cache asset_type discriminator.
-- All changes additive. No row modifications outside DEFAULT backfill.

-- Part A: scan_jobs retry machinery.
ALTER TABLE scan_jobs
    ADD COLUMN IF NOT EXISTS retry_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS next_retry_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS failure_class TEXT NOT NULL DEFAULT '';

-- Partial index for the SKIP LOCKED claim query. The next_retry_at filter
-- lives in the query predicate (NOW() is not IMMUTABLE, so it cannot appear
-- in an index predicate); this partial index still restricts to queued rows
-- which is the only set the claim loop ever scans.
DROP INDEX IF EXISTS idx_scan_jobs_queued;
CREATE INDEX idx_scan_jobs_queued ON scan_jobs (created_at)
    WHERE status = 'queued';

-- Part B: repo_scan_cache asset_type discriminator.
-- STEP 1 (load-bearing): add column with DEFAULT backfill so existing rows
-- get 'repository' before STEP 2 rebuilds the primary key including asset_type.
ALTER TABLE repo_scan_cache
    ADD COLUMN IF NOT EXISTS asset_type TEXT NOT NULL DEFAULT 'repository';

-- STEP 2: rebuild primary key.
ALTER TABLE repo_scan_cache DROP CONSTRAINT IF EXISTS repo_scan_cache_pkey;
ALTER TABLE repo_scan_cache
    ADD CONSTRAINT repo_scan_cache_pkey
    PRIMARY KEY (blob_sha, rule_version, prompt_content_hash, scan_mode, asset_type);

-- ==== from 044_cert_private_key_holding.sql ====
-- L4-F SP-1.6 — per-(host, cert) record of private-key holding.
-- Separate from asset_provenance because the evidence model is richer
-- (four evidence types) and the resolution path is independent of the
-- public-cert provenance graph. asset_provenance continues to record
-- public-cert holding; this table records private-key holding.

CREATE TABLE cert_private_key_holding (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id             UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    cert_fingerprint    TEXT NOT NULL REFERENCES certificates(fingerprint_sha256) ON DELETE CASCADE,
    evidence            TEXT NOT NULL,
    source              TEXT NOT NULL,
    source_detail       TEXT NOT NULL,
    first_seen          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (evidence IN (
        'colocated_pem',
        'pkcs12_entry',
        'jks_private_key_entry',
        'protected_path'
    )),
    UNIQUE (host_id, cert_fingerprint, evidence, source_detail)
);

CREATE INDEX idx_cert_pkh_cert_fp ON cert_private_key_holding (cert_fingerprint);
CREATE INDEX idx_cert_pkh_host    ON cert_private_key_holding (host_id);

-- ==== from 042_host_trust_store.sql ====
-- L4-F SP-1.6 — Trust-store inventory + SPKI fingerprint addition.
-- Spec: docs/superpowers/specs/2026-05-18-l4-f-sp1.6-pki-trusted-by-design.md
--
-- Universal layer — populated regardless of whether the CA's private key
-- is held by any inventory host. Public roots dominate (~150-200 per OS
-- bundle); that is expected and intentional for audit visibility.

CREATE TABLE host_trust_store (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id                 UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    ca_fingerprint_sha256   TEXT NOT NULL REFERENCES certificates(fingerprint_sha256) ON DELETE CASCADE,
    source                  TEXT NOT NULL,
    source_detail           TEXT NOT NULL,
    first_seen              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (source IN ('os_bundle', 'app_config', 'jvm_cacerts', 'lang_runtime')),
    UNIQUE (host_id, ca_fingerprint_sha256, source, source_detail)
);

CREATE INDEX idx_host_trust_store_ca_fp ON host_trust_store (ca_fingerprint_sha256);
CREATE INDEX idx_host_trust_store_host  ON host_trust_store (host_id);

-- SPKI fingerprint addition on certificates: SHA-256 of the cert's
-- RawSubjectPublicKeyInfo DER. Required for matching a private-key file
-- to its corresponding cert by public-key bytes during certfiles scanning.
-- Computed at parse time in certparse.parseDER; backfilled via re-parsing
-- raw_pem rows (extension to existing backfill-cert-aki-ski CLI).

ALTER TABLE certificates
    ADD COLUMN IF NOT EXISTS spki_fingerprint_sha256 TEXT;

CREATE INDEX IF NOT EXISTS idx_certificates_spki
    ON certificates (spki_fingerprint_sha256)
    WHERE spki_fingerprint_sha256 IS NOT NULL;

-- ==== from 021_application_tags.sql — application_tags ALTERs for repositories ====
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS application_tags TEXT[] NOT NULL DEFAULT '{}';


-- ──────────────────────────────────────────────────────────────────────
-- Baseline complete.
-- ──────────────────────────────────────────────────────────────────────
