//go:build integration

// Copyright 2026 net4n6-dev
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

// The Zeek poller re-reads a log after a cursor reset, a failed cursor save or
// a batch that failed part way, so recording the same session twice must not
// store it twice.

func obsCount(t *testing.T, st *PostgresStore, fp string) int {
	t.Helper()
	var n int
	require.NoError(t, st.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM observations WHERE cert_fingerprint = $1`, fp).Scan(&n))
	return n
}

func TestRecordObservation_SameSessionTwiceStoresOnce(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	fp := "obs-idem-0001"
	t.Cleanup(func() {
		_, _ = st.pool.Exec(ctx, `DELETE FROM certificates WHERE fingerprint_sha256 = $1`, fp)
	})
	require.NoError(t, st.UpsertCertificate(ctx, &model.Certificate{
		FingerprintSHA256: fp, RawPEM: "pem", SourceDiscovery: "api",
		FirstSeen: time.Now(), LastSeen: time.Now(),
	}))

	at := time.Now().Add(-time.Hour).Truncate(time.Microsecond)
	obs := func() *model.CertificateObservation {
		return &model.CertificateObservation{
			CertFingerprint: fp, ServerIP: "10.0.0.5", ServerPort: 443, ClientIP: "10.0.0.9",
			ServerName: "a.test", Source: model.SourceZeekPassive, ObservedAt: at,
		}
	}
	require.NoError(t, st.RecordObservation(ctx, obs()))
	require.NoError(t, st.RecordObservation(ctx, obs()), "a repeat must be a no-op, not an error")
	require.Equal(t, 1, obsCount(t, st, fp))

	// A different session (another client, or another moment) is still stored.
	other := obs()
	other.ClientIP = "10.0.0.10"
	require.NoError(t, st.RecordObservation(ctx, other))
	later := obs()
	later.ObservedAt = at.Add(time.Second)
	require.NoError(t, st.RecordObservation(ctx, later))
	require.Equal(t, 3, obsCount(t, st, fp))
}

// Installs that already stored duplicates keep one of each when the unique
// index is added.
func TestObservationsUniqueMigration_CollapsesExistingDuplicates(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	fp := "obs-idem-0002"
	t.Cleanup(func() {
		_, _ = st.pool.Exec(ctx, `DELETE FROM certificates WHERE fingerprint_sha256 = $1`, fp)
		_, _ = st.pool.Exec(ctx, `CREATE UNIQUE INDEX IF NOT EXISTS idx_obs_session_unique
			ON observations (cert_fingerprint, source, observed_at, client_ip, server_ip, server_port)`)
	})
	require.NoError(t, st.UpsertCertificate(ctx, &model.Certificate{
		FingerprintSHA256: fp, RawPEM: "pem", SourceDiscovery: "api",
		FirstSeen: time.Now(), LastSeen: time.Now(),
	}))

	// The state before the migration: no unique index, the session stored 3 times.
	_, err := st.pool.Exec(ctx, `DROP INDEX IF EXISTS idx_obs_session_unique`)
	require.NoError(t, err)
	for i := 0; i < 3; i++ {
		_, err := st.pool.Exec(ctx, `
			INSERT INTO observations (cert_fingerprint, server_ip, server_port, client_ip, source, observed_at)
			VALUES ($1, '10.0.0.5', 443, '10.0.0.9', 'zeek_passive', '2026-09-28T12:00:00Z')`, fp)
		require.NoError(t, err)
	}
	require.Equal(t, 3, obsCount(t, st, fp))

	sql, err := migrationsFS.ReadFile("migrations/v2.3.1_observations_unique.sql")
	require.NoError(t, err)
	_, err = st.pool.Exec(ctx, string(sql))
	require.NoError(t, err)
	require.Equal(t, 1, obsCount(t, st, fp))
}
