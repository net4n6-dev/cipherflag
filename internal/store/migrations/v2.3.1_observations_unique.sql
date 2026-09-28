-- observations was a plain INSERT with no key, so the same TLS session could be
-- stored again whenever a source re-read its input (the Zeek poller does after a
-- cursor reset, a failed cursor save or a batch that failed part way).
-- Collapse the duplicates already stored, then make a session unique so
-- RecordObservation can insert idempotently.
DELETE FROM observations
WHERE id IN (
    SELECT id FROM (
        SELECT id, row_number() OVER (
            PARTITION BY cert_fingerprint, source, observed_at, client_ip, server_ip, server_port
            ORDER BY id
        ) AS rn
        FROM observations
    ) ranked
    WHERE rn > 1
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_obs_session_unique
    ON observations (cert_fingerprint, source, observed_at, client_ip, server_ip, server_port);
