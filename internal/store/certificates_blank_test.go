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

// ListBlankCertificatesWithPEM finds the rows earlier versions stored blank
// (a PEM-only discovery kept only its fingerprint) that can still be
// repaired from their stored PEM. serve repairs them at startup.
func TestListBlankCertificatesWithPEM(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	seen := time.Now().Add(-time.Hour).Truncate(time.Microsecond)

	put := func(c *model.Certificate) {
		t.Helper()
		c.FirstSeen, c.LastSeen = seen, seen
		require.NoError(t, st.UpsertCertificate(ctx, c))
		t.Cleanup(func() {
			_, _ = st.pool.Exec(ctx, `DELETE FROM certificates WHERE fingerprint_sha256 = $1`, c.FingerprintSHA256)
		})
	}
	put(&model.Certificate{FingerprintSHA256: "blank-b", RawPEM: "pem-b", SourceDiscovery: "api"})
	put(&model.Certificate{FingerprintSHA256: "blank-a", RawPEM: "pem-a", SourceDiscovery: "api"})
	put(&model.Certificate{FingerprintSHA256: "blank-c", RawPEM: "pem-c", SourceDiscovery: "api"})
	put(&model.Certificate{FingerprintSHA256: "blank-no-pem"}) // nothing to repair from
	put(&model.Certificate{                                    // complete: not blank
		FingerprintSHA256: "complete",
		Subject:           model.DistinguishedName{CommonName: "complete.test"},
		NotAfter:          time.Now().Add(24 * time.Hour),
		RawPEM:            "pem-complete",
	})

	page1, err := st.ListBlankCertificatesWithPEM(ctx, "", 2)
	require.NoError(t, err)
	require.Len(t, page1, 2)
	require.Equal(t, "blank-a", page1[0].FingerprintSHA256)
	require.Equal(t, "blank-b", page1[1].FingerprintSHA256)
	require.Equal(t, "pem-a", page1[0].RawPEM)
	require.True(t, page1[0].LastSeen.Equal(seen), "LastSeen is returned so a repair can keep it")

	page2, err := st.ListBlankCertificatesWithPEM(ctx, page1[1].FingerprintSHA256, 2)
	require.NoError(t, err)
	require.Len(t, page2, 1)
	require.Equal(t, "blank-c", page2[0].FingerprintSHA256)

	page3, err := st.ListBlankCertificatesWithPEM(ctx, page2[0].FingerprintSHA256, 2)
	require.NoError(t, err)
	require.Empty(t, page3)
}

// The no-op case runs on every startup, so it must be an index probe, not a
// scan of every certificate.
func TestListBlankCertificatesWithPEM_IsAnIndexProbe(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	// One connection: SET applies per session.
	conn, err := st.pool.Acquire(ctx)
	require.NoError(t, err)
	defer conn.Release()
	_, err = conn.Exec(ctx, `SET enable_seqscan = off`)
	require.NoError(t, err)
	defer func() { _, _ = conn.Exec(ctx, `RESET enable_seqscan`) }()
	var plan string
	rows, err := conn.Query(ctx, `EXPLAIN `+listBlankCertificatesSQL, "", 500)
	require.NoError(t, err)
	for rows.Next() {
		var line string
		require.NoError(t, rows.Scan(&line))
		plan += line + "\n"
	}
	require.NoError(t, rows.Err())
	// Served by idx_certs_not_after (v2.0 baseline): the zero not_after is an
	// index condition, so only blank rows are visited.
	require.Contains(t, plan, "Index Cond: (not_after = '0001-01-01 00:00:00+00'", "plan:\n%s", plan)
}
