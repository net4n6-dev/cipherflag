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

func TestUpsertPrivateKeyHoldings_InsertsAndUpdatesLastSeen(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	hostID := seedTestHost(t, st, "host1")
	if err := st.UpsertCertificate(ctx, minCert("cert-fp")); err != nil {
		t.Fatalf("seedCert: %v", err)
	}

	obs := []model.PrivateKeyObservation{{
		HostID:          hostID,
		CertFingerprint: "cert-fp",
		Evidence:        "colocated_pem",
		Source:          "certfiles",
		SourceDetail:    "/etc/ssl/key.pem",
	}}
	if err := st.UpsertPrivateKeyHoldings(ctx, obs); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	var first, last time.Time
	if err := st.Pool().QueryRow(ctx,
		`SELECT first_seen, last_seen FROM cert_private_key_holding
		 WHERE host_id = $1 AND cert_fingerprint = $2`,
		hostID, "cert-fp",
	).Scan(&first, &last); err != nil {
		t.Fatalf("query: %v", err)
	}
	if !first.Equal(last) {
		t.Errorf("first_seen != last_seen on first insert: %v vs %v", first, last)
	}

	time.Sleep(10 * time.Millisecond)
	if err := st.UpsertPrivateKeyHoldings(ctx, obs); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	var first2, last2 time.Time
	st.Pool().QueryRow(ctx,
		`SELECT first_seen, last_seen FROM cert_private_key_holding
		 WHERE host_id = $1 AND cert_fingerprint = $2`,
		hostID, "cert-fp",
	).Scan(&first2, &last2)
	if !first.Equal(first2) {
		t.Errorf("first_seen mutated: was %v, now %v", first, first2)
	}
	if !last2.After(last) {
		t.Errorf("last_seen not advanced: was %v, now %v", last, last2)
	}
}

func TestHostsHoldingCAKey_ExcludesProtectedPath(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	hostStrong := seedTestHost(t, st, "host_strong")
	hostWeak := seedTestHost(t, st, "host_weak")
	if err := st.UpsertCertificate(ctx, minCert("ca-fp")); err != nil {
		t.Fatalf("seedCert: %v", err)
	}
	if err := st.UpsertPrivateKeyHoldings(ctx, []model.PrivateKeyObservation{
		{HostID: hostStrong, CertFingerprint: "ca-fp", Evidence: "colocated_pem",
			Source: "certfiles", SourceDetail: "/etc/ssl/private/ca.pem"},
		{HostID: hostWeak, CertFingerprint: "ca-fp", Evidence: "protected_path",
			Source: "certfiles", SourceDetail: "/etc/ssl/private/"},
	}); err != nil {
		t.Fatal(err)
	}

	got, err := st.HostsHoldingCAKey(ctx, "ca-fp", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].HostID != hostStrong {
		t.Errorf("scoring-path query got %+v, want [host_strong (%s)]", got, hostStrong)
	}

	gotInferred, _ := st.HostsHoldingCAKey(ctx, "ca-fp", true)
	if len(gotInferred) != 2 {
		t.Errorf("display-path query got %d holders, want 2", len(gotInferred))
	}
}

func TestPruneStalePrivateKeyHoldings_DeletesBeforeWatermark(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	hostID := seedTestHost(t, st, "host1")
	if err := st.UpsertCertificate(ctx, minCert("cert-fp")); err != nil {
		t.Fatalf("seedCert: %v", err)
	}
	if err := st.UpsertPrivateKeyHoldings(ctx, []model.PrivateKeyObservation{{
		HostID: hostID, CertFingerprint: "cert-fp", Evidence: "colocated_pem",
		Source: "certfiles", SourceDetail: "/etc/ssl/key.pem",
	}}); err != nil {
		t.Fatal(err)
	}
	st.Pool().Exec(ctx, `UPDATE cert_private_key_holding SET last_seen = NOW() - INTERVAL '1 hour'`)

	watermark := time.Now().Add(-30 * time.Minute)
	n, err := st.PruneStalePrivateKeyHoldings(ctx, hostID, "certfiles", watermark)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("pruned %d, want 1", n)
	}
}
