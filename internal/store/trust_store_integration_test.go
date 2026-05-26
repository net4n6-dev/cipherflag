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

	"github.com/net4n6-dev/cipherflag/internal/model"
)

func TestUpsertTrustStoreObservations_DedupesOnTuple(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	hostID := seedTestHost(t, st, "h1")
	if err := st.UpsertCertificate(ctx, minCert("ca1")); err != nil {
		t.Fatal(err)
	}

	obs := []model.TrustStoreObservation{{
		HostID:        hostID,
		CAFingerprint: "ca1",
		Source:        "os_bundle",
		SourceDetail:  "/etc/ssl/certs/ca-certificates.crt",
	}}
	if err := st.UpsertTrustStoreObservations(ctx, obs); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertTrustStoreObservations(ctx, obs); err != nil {
		t.Fatal(err)
	}

	var count int
	if err := st.Pool().QueryRow(ctx,
		`SELECT COUNT(*) FROM host_trust_store WHERE host_id = $1`, hostID,
	).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("count = %d, want 1 (UNIQUE constraint should dedupe)", count)
	}
}

func TestListTrustStoreHoldingsForHost_GroupsBySource(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	hostID := seedTestHost(t, st, "h1")
	if err := st.UpsertCertificate(ctx, minCert("ca1")); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertCertificate(ctx, minCert("ca2")); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertTrustStoreObservations(ctx, []model.TrustStoreObservation{
		{HostID: hostID, CAFingerprint: "ca1", Source: "os_bundle", SourceDetail: "/etc/ssl/certs/ca-certificates.crt"},
		{HostID: hostID, CAFingerprint: "ca1", Source: "app_config", SourceDetail: "nginx:/etc/nginx/conf.d/api.conf:ssl_trusted_certificate"},
		{HostID: hostID, CAFingerprint: "ca2", Source: "jvm_cacerts", SourceDetail: "/usr/lib/jvm/default/lib/security/cacerts"},
	}); err != nil {
		t.Fatal(err)
	}
	holdings, err := st.ListTrustStoreHoldingsForHost(ctx, hostID)
	if err != nil {
		t.Fatal(err)
	}
	if len(holdings) != 3 {
		t.Errorf("got %d holdings, want 3", len(holdings))
	}
}

func TestPruneStaleTrustStoreRows_ByHostAndSource(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	hostID := seedTestHost(t, st, "h1")
	if err := st.UpsertCertificate(ctx, minCert("ca1")); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertTrustStoreObservations(ctx, []model.TrustStoreObservation{{
		HostID: hostID, CAFingerprint: "ca1",
		Source: "os_bundle", SourceDetail: "/etc/ssl/certs/ca-certificates.crt",
	}}); err != nil {
		t.Fatal(err)
	}
	st.Pool().Exec(ctx, `UPDATE host_trust_store SET last_seen = NOW() - INTERVAL '1 hour'`)
	n, err := st.PruneStaleTrustStoreRows(ctx, hostID, "os_bundle", time.Now().Add(-30*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("pruned %d, want 1", n)
	}
}
