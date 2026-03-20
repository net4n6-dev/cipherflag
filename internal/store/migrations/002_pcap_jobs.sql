CREATE TABLE IF NOT EXISTS pcap_jobs (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    filename      TEXT NOT NULL,
    file_size     BIGINT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'queued',
    certs_found   INTEGER DEFAULT 0,
    certs_new     INTEGER DEFAULT 0,
    error         TEXT,
    created_at    TIMESTAMPTZ DEFAULT now(),
    completed_at  TIMESTAMPTZ
);
