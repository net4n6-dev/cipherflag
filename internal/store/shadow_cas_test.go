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
	"strings"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

// Test-wide clock so the observation-window math in the unattributed
// / host-impact enrichment stays deterministic across cases.
// shadowCATestNow is the reference "now" used by every test in this
// file. Initialized at package-load time to the real wall-clock so the
// production query's `NOW() - INTERVAL '30 days'` filter (shadow_cas.go:110)
// stays consistent with the relative offsets we seed. A previously-fixed
// date (time.Date(2026,4,20,...)) aged out of the recent-children window
// once real time advanced past it — see this test's pre-existing-failure
// fix.
var shadowCATestNow = time.Now().UTC()

// seedShadowCATestCA inserts a CA cert and returns its fingerprint.
// Optional `daysOld` makes `first_seen` deterministic so the
// recent_children_count test can hinge on it.
func seedShadowCATestCA(t *testing.T, st *PostgresStore, suffix string, isCA bool, daysOld int) string {
	t.Helper()
	ctx := context.Background()
	cert := &model.Certificate{
		FingerprintSHA256: "sha256:shadow-ca-test-" + suffix,
		Subject: model.DistinguishedName{
			CommonName:   "ShadowCATest-" + suffix,
			Organization: "TestOrg",
		},
		Issuer:          model.DistinguishedName{CommonName: "Root-" + suffix},
		SerialNumber:    "serial-" + suffix,
		NotBefore:       shadowCATestNow.AddDate(0, 0, -daysOld-1),
		NotAfter:        shadowCATestNow.AddDate(1, 0, 0),
		KeyAlgorithm:    model.KeyRSA,
		KeySizeBits:     2048,
		IsCA:            isCA,
		SourceDiscovery: model.SourceZeekPassive,
		FirstSeen:       shadowCATestNow.AddDate(0, 0, -daysOld),
		LastSeen:        shadowCATestNow,
	}
	if err := st.UpsertCertificate(ctx, cert); err != nil {
		t.Fatalf("seed cert %s: %v", cert.FingerprintSHA256, err)
	}
	return cert.FingerprintSHA256
}

// seedShadowCATestLeaf inserts a leaf whose issuer_cn matches the
// given CA's subject_cn (so it counts toward direct_children_count).
func seedShadowCATestLeaf(t *testing.T, st *PostgresStore, caSubjectCN, suffix string, daysOld int) string {
	t.Helper()
	ctx := context.Background()
	cert := &model.Certificate{
		FingerprintSHA256: "sha256:shadow-leaf-" + suffix,
		Subject:           model.DistinguishedName{CommonName: "leaf-" + suffix + ".example.com"},
		Issuer:            model.DistinguishedName{CommonName: caSubjectCN},
		SerialNumber:      "leaf-serial-" + suffix,
		NotBefore:         shadowCATestNow.AddDate(0, 0, -daysOld-1),
		NotAfter:          shadowCATestNow.AddDate(0, 6, 0),
		KeyAlgorithm:      model.KeyRSA,
		KeySizeBits:       2048,
		IsCA:              false,
		SourceDiscovery:   model.SourceZeekPassive,
		FirstSeen:         shadowCATestNow.AddDate(0, 0, -daysOld),
		LastSeen:          shadowCATestNow,
	}
	if err := st.UpsertCertificate(ctx, cert); err != nil {
		t.Fatalf("seed leaf %s: %v", cert.FingerprintSHA256, err)
	}
	return cert.FingerprintSHA256
}

func TestListShadowCAs_EmptyDeclaredRegistryReturnsAllCAs(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	caA := seedShadowCATestCA(t, st, "a", true, 100)
	caB := seedShadowCATestCA(t, st, "b", true, 100)
	// A leaf — MUST NOT appear in the shadow list.
	_ = seedShadowCATestCA(t, st, "leaf-direct", false, 10)

	shadows, err := st.ListShadowCAs(ctx)
	if err != nil {
		t.Fatalf("list shadow cas: %v", err)
	}
	if len(shadows) != 2 {
		t.Fatalf("shadow count = %d, want 2", len(shadows))
	}
	seen := map[string]bool{}
	for _, s := range shadows {
		seen[s.FingerprintSHA256] = true
		if !strings.HasPrefix(s.FingerprintSHA256, "sha256:shadow-ca-test-") {
			continue // test isolation — other tests' data shouldn't leak in via truncate, but be defensive
		}
	}
	if !seen[caA] || !seen[caB] {
		t.Errorf("expected both CAs in shadow list; got %v", seen)
	}
}

func TestListShadowCAs_DeclaredCARemovedFromShadow(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	caA := seedShadowCATestCA(t, st, "a", true, 100)
	caB := seedShadowCATestCA(t, st, "b", true, 100)

	if err := st.DeclareCA(ctx, &DeclareCARequest{
		FingerprintSHA256: caA,
		OwnerTeam:         "platform",
		Note:              "internal root",
	}); err != nil {
		t.Fatalf("declare caA: %v", err)
	}

	shadows, err := st.ListShadowCAs(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(shadows) != 1 {
		t.Fatalf("shadow count after declaring caA = %d, want 1", len(shadows))
	}
	if shadows[0].FingerprintSHA256 != caB {
		t.Errorf("shadow[0] = %q, want %q (caB — the undeclared one)", shadows[0].FingerprintSHA256, caB)
	}

	declared, err := st.ListDeclaredCAs(ctx)
	if err != nil {
		t.Fatalf("list declared: %v", err)
	}
	if len(declared) != 1 {
		t.Fatalf("declared count = %d, want 1", len(declared))
	}
	if declared[0].OwnerTeam != "platform" || declared[0].Note != "internal root" {
		t.Errorf("declared metadata = %+v, want owner_team=platform + note", declared[0])
	}
}

func TestDeclareCA_UpsertUpdatesMetadata(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	ca := seedShadowCATestCA(t, st, "upsert", true, 50)
	if err := st.DeclareCA(ctx, &DeclareCARequest{
		FingerprintSHA256: ca, OwnerTeam: "initial-team", Note: "initial",
	}); err != nil {
		t.Fatalf("first declare: %v", err)
	}
	if err := st.DeclareCA(ctx, &DeclareCARequest{
		FingerprintSHA256: ca, OwnerTeam: "updated-team", Note: "revised",
	}); err != nil {
		t.Fatalf("second declare: %v", err)
	}
	declared, err := st.ListDeclaredCAs(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(declared) != 1 {
		t.Fatalf("declared count = %d, want 1 (upsert must not duplicate)", len(declared))
	}
	if declared[0].OwnerTeam != "updated-team" || declared[0].Note != "revised" {
		t.Errorf("metadata not updated on upsert: %+v", declared[0])
	}
}

func TestDeclareCA_RejectsLeafFingerprint(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	leaf := seedShadowCATestCA(t, st, "leaf-only", false, 10)

	err := st.DeclareCA(ctx, &DeclareCARequest{FingerprintSHA256: leaf})
	if err == nil {
		t.Fatal("expected error declaring a leaf as CA")
	}
	if !strings.Contains(err.Error(), "is a leaf") {
		t.Errorf("err = %v, want 'is a leaf'", err)
	}
}

func TestDeclareCA_RejectsUnknownFingerprint(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	err := st.DeclareCA(ctx, &DeclareCARequest{FingerprintSHA256: "sha256:never-seen"})
	if err == nil {
		t.Fatal("expected error declaring unknown fingerprint")
	}
	if !strings.Contains(err.Error(), "not in certificates") {
		t.Errorf("err = %v, want 'not in certificates'", err)
	}
}

func TestRevokeDeclaredCA_MovesBackToShadow(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	ca := seedShadowCATestCA(t, st, "revoke", true, 100)
	if err := st.DeclareCA(ctx, &DeclareCARequest{FingerprintSHA256: ca}); err != nil {
		t.Fatalf("declare: %v", err)
	}

	// Confirm not shadow.
	shadows, _ := st.ListShadowCAs(ctx)
	for _, s := range shadows {
		if s.FingerprintSHA256 == ca {
			t.Fatal("CA should not be in shadow list after declare")
		}
	}

	if err := st.RevokeDeclaredCA(ctx, ca); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	shadows, _ = st.ListShadowCAs(ctx)
	found := false
	for _, s := range shadows {
		if s.FingerprintSHA256 == ca {
			found = true
		}
	}
	if !found {
		t.Error("CA should reappear in shadow list after revoke")
	}
}

func TestRevokeDeclaredCA_IdempotentOnUnknown(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	// Revoking a fingerprint that was never declared must return nil.
	if err := st.RevokeDeclaredCA(ctx, "sha256:never-declared"); err != nil {
		t.Errorf("revoke on undeclared fingerprint should be nil, got %v", err)
	}
}

func TestIsDeclared_ReflectsRegistry(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	ca := seedShadowCATestCA(t, st, "is-declared", true, 100)

	ok, err := st.IsDeclared(ctx, ca)
	if err != nil {
		t.Fatalf("IsDeclared pre-declare: %v", err)
	}
	if ok {
		t.Error("IsDeclared=true before declaring")
	}

	_ = st.DeclareCA(ctx, &DeclareCARequest{FingerprintSHA256: ca})

	ok, err = st.IsDeclared(ctx, ca)
	if err != nil {
		t.Fatalf("IsDeclared post-declare: %v", err)
	}
	if !ok {
		t.Error("IsDeclared=false after declaring")
	}
}

// TestListShadowCAs_EnrichmentDirectChildren exercises the
// direct_children_count column: leaves whose issuer_cn matches the
// CA's subject_cn must be counted; leaves from a different CA must
// not. Self-matches (the CA counting itself) must be excluded.
func TestListShadowCAs_EnrichmentDirectChildren(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	ca := seedShadowCATestCA(t, st, "ench", true, 100)
	// The CA's subject_cn = "ShadowCATest-ench" per seedShadowCATestCA.
	seedShadowCATestLeaf(t, st, "ShadowCATest-ench", "ench-1", 50)
	seedShadowCATestLeaf(t, st, "ShadowCATest-ench", "ench-2", 10) // recent
	seedShadowCATestLeaf(t, st, "ShadowCATest-ench", "ench-3", 3)  // recent
	// An unrelated leaf under a different issuer — must NOT count.
	seedShadowCATestLeaf(t, st, "SomeOtherCA", "unrelated", 5)

	shadows, err := st.ListShadowCAs(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	var found *ShadowCA
	for i := range shadows {
		if shadows[i].FingerprintSHA256 == ca {
			found = &shadows[i]
			break
		}
	}
	if found == nil {
		t.Fatal("seeded CA not in shadow list")
	}
	if found.DirectChildrenCount != 3 {
		t.Errorf("DirectChildrenCount = %d, want 3 (leaves ench-1/2/3 under this CA)", found.DirectChildrenCount)
	}
	if found.RecentChildrenCount != 2 {
		t.Errorf("RecentChildrenCount = %d, want 2 (ench-2 + ench-3 within last 30d)", found.RecentChildrenCount)
	}
}

// TestListShadowCAs_EnrichmentUnattributedIPs exercises the v1.5.0
// cross-reference: observations for leaves under a shadow CA whose
// server_ip finds no host_ip_sighting should count toward
// unattributed_ips. Feeds the "candidate shadow asset" triage path.
// TestDeclareCA_HolderHostIDRoundTrip verifies that a CA declared with a
// holder_host_id value is persisted and returned correctly by ListDeclaredCAs.
// Covers migration 045: ADD COLUMN holder_host_id + DeclareCA upsert extension.
func TestDeclareCA_HolderHostIDRoundTrip(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	ca := seedShadowCATestCA(t, st, "holder-rt", true, 30)
	holderHost := seedTestHost(t, st, "holder-host.example.com")

	if err := st.DeclareCA(ctx, &DeclareCARequest{
		FingerprintSHA256: ca,
		OwnerTeam:         "infra",
		Note:              "HSM-resident root",
		HolderHostID:      holderHost,
	}); err != nil {
		t.Fatalf("DeclareCA with holder: %v", err)
	}

	declared, err := st.ListDeclaredCAs(ctx)
	if err != nil {
		t.Fatalf("ListDeclaredCAs: %v", err)
	}
	if len(declared) != 1 {
		t.Fatalf("expected 1 declared CA, got %d", len(declared))
	}
	got := declared[0]
	if got.HolderHostID != holderHost {
		t.Errorf("HolderHostID = %q, want %q", got.HolderHostID, holderHost)
	}
	if got.OwnerTeam != "infra" || got.Note != "HSM-resident root" {
		t.Errorf("other metadata = %+v, want infra / HSM-resident root", got)
	}
}

// TestDeclareCA_HolderHostIDUpsertUpdates verifies that a second DeclareCA call
// on the same fingerprint updates holder_host_id via ON CONFLICT DO UPDATE.
func TestDeclareCA_HolderHostIDUpsertUpdates(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	ca := seedShadowCATestCA(t, st, "holder-upsert", true, 30)
	host1 := seedTestHost(t, st, "host1.example.com")
	host2 := seedTestHost(t, st, "host2.example.com")

	// First declare: no holder.
	if err := st.DeclareCA(ctx, &DeclareCARequest{
		FingerprintSHA256: ca,
		OwnerTeam:         "team-a",
	}); err != nil {
		t.Fatalf("initial declare: %v", err)
	}

	// Second declare: set holder to host1.
	if err := st.DeclareCA(ctx, &DeclareCARequest{
		FingerprintSHA256: ca,
		OwnerTeam:         "team-a",
		HolderHostID:      host1,
	}); err != nil {
		t.Fatalf("upsert with holder: %v", err)
	}

	declared, _ := st.ListDeclaredCAs(ctx)
	if len(declared) != 1 {
		t.Fatalf("expected 1 declared CA after upsert, got %d", len(declared))
	}
	if declared[0].HolderHostID != host1 {
		t.Errorf("after upsert: HolderHostID = %q, want %q (host1)", declared[0].HolderHostID, host1)
	}

	// Third declare: change holder to host2, verify update.
	if err := st.DeclareCA(ctx, &DeclareCARequest{
		FingerprintSHA256: ca,
		OwnerTeam:         "team-a",
		HolderHostID:      host2,
	}); err != nil {
		t.Fatalf("upsert holder change: %v", err)
	}

	declared, _ = st.ListDeclaredCAs(ctx)
	if declared[0].HolderHostID != host2 {
		t.Errorf("after holder change: HolderHostID = %q, want %q (host2)", declared[0].HolderHostID, host2)
	}

	// Fourth declare: clear the holder (empty string → NULL).
	if err := st.DeclareCA(ctx, &DeclareCARequest{
		FingerprintSHA256: ca,
		OwnerTeam:         "team-a",
	}); err != nil {
		t.Fatalf("upsert clear holder: %v", err)
	}

	declared, _ = st.ListDeclaredCAs(ctx)
	if declared[0].HolderHostID != "" {
		t.Errorf("after clearing holder: HolderHostID = %q, want empty", declared[0].HolderHostID)
	}
}

func TestListShadowCAs_EnrichmentUnattributedIPs(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	ca := seedShadowCATestCA(t, st, "unattr", true, 100)
	leaf := seedShadowCATestLeaf(t, st, "ShadowCATest-unattr", "unattr-1", 10)

	// Seed two observations on different IPs. No host_ip_sightings —
	// both should land as unattributed.
	for _, ip := range []string{"198.51.100.10", "198.51.100.11"} {
		if _, err := st.pool.Exec(ctx, `
			INSERT INTO observations (cert_fingerprint, server_ip, server_port, server_name, observed_at, source)
			VALUES ($1, $2, 443, 'test', $3, 'zeek_passive')
		`, leaf, ip, shadowCATestNow.Add(-2*time.Hour)); err != nil {
			t.Fatalf("seed obs: %v", err)
		}
	}

	shadows, err := st.ListShadowCAs(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var found *ShadowCA
	for i := range shadows {
		if shadows[i].FingerprintSHA256 == ca {
			found = &shadows[i]
		}
	}
	if found == nil {
		t.Fatal("seeded CA missing from shadow list")
	}
	if found.UnattributedIPs != 2 {
		t.Errorf("UnattributedIPs = %d, want 2 (distinct 198.51.100.10 + 11)", found.UnattributedIPs)
	}
	if found.HostImpact != 0 {
		t.Errorf("HostImpact = %d, want 0 (no sightings seeded)", found.HostImpact)
	}
}
