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

	"github.com/stretchr/testify/require"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

// A row the upsert cannot write (here: a CA that is not in certificates, so
// the foreign key refuses it) used to be logged and forgotten. The upserts
// now report failures per source, so scan-truststore never treats a store it
// could not fully write as scanned and prunes it.
func TestUpsertTrustStoreObservations_ReportsFailedRowsBySource(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	hostID := seedTestHost(t, st, "failures-trust")
	require.NoError(t, st.UpsertCertificate(ctx, minCert("known-ca")))

	failed, err := st.UpsertTrustStoreObservations(ctx, []model.TrustStoreObservation{
		{HostID: hostID, CAFingerprint: "known-ca", Source: "os_bundle", SourceDetail: "/etc/ssl/certs/a.pem"},
		{HostID: hostID, CAFingerprint: "unknown-ca-1", Source: "jvm_cacerts", SourceDetail: "/jvm/cacerts"},
		{HostID: hostID, CAFingerprint: "known-ca", Source: "lang_runtime", SourceDetail: "/usr/lib/python3/certifi/cacert.pem"},
		{HostID: hostID, CAFingerprint: "unknown-ca-2", Source: "jvm_cacerts", SourceDetail: "/jvm/cacerts"},
	})
	require.NoError(t, err)
	require.Equal(t, map[BundleScope]int{{Source: "jvm_cacerts", SourceDetail: "/jvm/cacerts"}: 2}, failed)

	// A failed row must not take the rest of the batch with it: both good
	// rows, before and after a failure, are stored.
	rows, err := st.ListTrustStoreHoldingsForHost(ctx, hostID)
	require.NoError(t, err)
	var sources []string
	for _, r := range rows {
		sources = append(sources, r.Source)
	}
	require.ElementsMatch(t, []string{"os_bundle", "lang_runtime"}, sources)
}

func TestUpsertPrivateKeyHoldings_ReportsFailedRowsBySource(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	hostID := seedTestHost(t, st, "failures-keys")
	require.NoError(t, st.UpsertCertificate(ctx, minCert("known-cert")))
	require.NoError(t, st.UpsertCertificate(ctx, minCert("known-cert-2")))

	failed, err := st.UpsertPrivateKeyHoldings(ctx, []model.PrivateKeyObservation{
		{HostID: hostID, CertFingerprint: "known-cert", Evidence: "jks_private_key_entry", Source: "truststore", SourceDetail: "/a.jks"},
		{HostID: hostID, CertFingerprint: "unknown-cert", Evidence: "jks_private_key_entry", Source: "truststore", SourceDetail: "/b.jks"},
		{HostID: hostID, CertFingerprint: "known-cert-2", Evidence: "pkcs12_entry", Source: "truststore", SourceDetail: "/c.p12"},
	})
	require.NoError(t, err)
	require.Equal(t, map[BundleScope]int{{Source: "truststore", SourceDetail: "/b.jks"}: 1}, failed)

	// Both good rows, before and after the failure, are stored.
	for _, fp := range []string{"known-cert", "known-cert-2"} {
		holders, err := st.HostsHoldingCAKey(ctx, fp, true)
		require.NoError(t, err)
		require.Len(t, holders, 1, "%s must be stored", fp)
	}
}

// The prune cutoff is taken from the database clock, which stamps last_seen,
// so a scanned host whose clock runs ahead of the database cannot make a
// scan delete the rows it has just written.
func TestDatabaseNow_IsTheClockThatStampsLastSeen(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	hostID := seedTestHost(t, st, "db-clock")
	require.NoError(t, st.UpsertCertificate(ctx, minCert("clock-ca")))

	before, err := st.DatabaseNow(ctx)
	require.NoError(t, err)
	_, err = st.UpsertTrustStoreObservations(ctx, []model.TrustStoreObservation{
		{HostID: hostID, CAFingerprint: "clock-ca", Source: "os_bundle", SourceDetail: "/etc/ssl/certs/c.pem"},
	})
	require.NoError(t, err)

	rows, err := st.ListTrustStoreHoldingsForHost(ctx, hostID)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.False(t, rows[0].LastSeen.Before(before), "a row written after DatabaseNow must not be before it")

	n, err := st.PruneStaleTrustStoreRows(ctx, hostID, "os_bundle", "/etc/ssl/certs/c.pem", before)
	require.NoError(t, err)
	require.Zero(t, n, "pruning at the pre-write watermark must keep the row just written")
}

// Pruning is scoped to one bundle: a scan removes stale rows only for the
// bundles it read, never for a sibling bundle of the same source that it
// did not read.
func TestPruneStaleTrustStoreRows_ScopedToOneBundle(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	hostID := seedTestHost(t, st, "prune-bundle")
	require.NoError(t, st.UpsertCertificate(ctx, minCert("bundle-ca")))
	_, err := st.UpsertTrustStoreObservations(ctx, []model.TrustStoreObservation{
		{HostID: hostID, CAFingerprint: "bundle-ca", Source: "os_bundle", SourceDetail: "/etc/ssl/read.pem"},
		{HostID: hostID, CAFingerprint: "bundle-ca", Source: "os_bundle", SourceDetail: "/etc/ssl/not-read.pem"},
	})
	require.NoError(t, err)
	after, err := st.DatabaseNow(ctx)
	require.NoError(t, err)

	n, err := st.PruneStaleTrustStoreRows(ctx, hostID, "os_bundle", "/etc/ssl/read.pem", after)
	require.NoError(t, err)
	require.EqualValues(t, 1, n)

	rows, err := st.ListTrustStoreHoldingsForHost(ctx, hostID)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Equal(t, "/etc/ssl/not-read.pem", rows[0].SourceDetail, "the bundle that was not read keeps its row")
}
