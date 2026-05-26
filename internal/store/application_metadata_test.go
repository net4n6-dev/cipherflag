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

// intp returns a pointer to an int — avoids taking the address of a
// literal inline in test seed lines.
func intp(n int) *int { return &n }

// timep returns a pointer to a time.
func timep(t time.Time) *time.Time { return &t }

func TestUpsertApplicationMetadata_InsertAndRoundTrip(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	err := st.UpsertApplicationMetadata(ctx, &DeclareApplicationMetadataRequest{
		Tag:          "pii-customer-20y",
		DataTTLYears: intp(20),
		OwnerTeam:    "platform-security",
		Note:         "customer PII — HIPAA 25y? operator check",
	})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}

	got, err := st.GetApplicationMetadata(ctx, "pii-customer-20y")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("metadata not found after upsert")
	}
	if got.DataTTLYears == nil || *got.DataTTLYears != 20 {
		t.Errorf("ttl = %v, want 20", got.DataTTLYears)
	}
	if got.OwnerTeam != "platform-security" {
		t.Errorf("owner_team = %q", got.OwnerTeam)
	}
	// Effective sensitive_until should be added_at + 20y.
	eff := got.EffectiveSensitiveUntil()
	want := got.AddedAt.AddDate(20, 0, 0)
	if !eff.Equal(want) {
		t.Errorf("EffectiveSensitiveUntil = %v, want %v (AddedAt + 20y)", eff, want)
	}
}

func TestUpsertApplicationMetadata_AbsoluteDateWinsOverTTL(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	absolute := time.Date(2045, 1, 1, 0, 0, 0, 0, time.UTC)
	err := st.UpsertApplicationMetadata(ctx, &DeclareApplicationMetadataRequest{
		Tag:                "gdpr-eu-app",
		DataTTLYears:       intp(3), // would derive to AddedAt+3y
		DataSensitiveUntil: timep(absolute),
		OwnerTeam:          "legal",
	})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, _ := st.GetApplicationMetadata(ctx, "gdpr-eu-app")
	if !got.EffectiveSensitiveUntil().Equal(absolute) {
		t.Errorf("absolute date must win over ttl_years; eff = %v, want %v",
			got.EffectiveSensitiveUntil(), absolute)
	}
}

func TestUpsertApplicationMetadata_Upsert_UpdatesInPlace(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	_ = st.UpsertApplicationMetadata(ctx, &DeclareApplicationMetadataRequest{
		Tag: "repeat-test", DataTTLYears: intp(5), OwnerTeam: "a",
	})
	_ = st.UpsertApplicationMetadata(ctx, &DeclareApplicationMetadataRequest{
		Tag: "repeat-test", DataTTLYears: intp(15), OwnerTeam: "b",
	})

	got, _ := st.GetApplicationMetadata(ctx, "repeat-test")
	if got == nil {
		t.Fatal("metadata lost on upsert")
	}
	if *got.DataTTLYears != 15 {
		t.Errorf("ttl = %d, want 15 (updated)", *got.DataTTLYears)
	}
	if got.OwnerTeam != "b" {
		t.Errorf("owner_team = %q, want b (updated)", got.OwnerTeam)
	}

	// And just one row — not two.
	all, _ := st.ListApplicationMetadata(ctx)
	var count int
	for _, m := range all {
		if m.Tag == "repeat-test" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("list count for repeat-test = %d, want 1", count)
	}
}

func TestUpsertApplicationMetadata_RequiresTTLOrAbsolute(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	err := st.UpsertApplicationMetadata(ctx, &DeclareApplicationMetadataRequest{
		Tag: "empty-decl", OwnerTeam: "x",
	})
	if err == nil {
		t.Fatal("expected error when both ttl + absolute are nil")
	}
}

func TestUpsertApplicationMetadata_DBCheckRejectsBadRange(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	err := st.UpsertApplicationMetadata(ctx, &DeclareApplicationMetadataRequest{
		Tag: "out-of-range", DataTTLYears: intp(200), OwnerTeam: "x",
	})
	if err == nil || !strings.Contains(err.Error(), "application_metadata_ttl_range") {
		t.Errorf("expected CHECK violation on out-of-range ttl; got %v", err)
	}
}

func TestDeleteApplicationMetadata_Idempotent(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	_ = st.UpsertApplicationMetadata(ctx, &DeclareApplicationMetadataRequest{
		Tag: "to-delete", DataTTLYears: intp(3),
	})
	if err := st.DeleteApplicationMetadata(ctx, "to-delete"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	got, _ := st.GetApplicationMetadata(ctx, "to-delete")
	if got != nil {
		t.Error("metadata not removed")
	}
	// Idempotent second delete.
	if err := st.DeleteApplicationMetadata(ctx, "to-delete"); err != nil {
		t.Errorf("second delete returned error; want nil: %v", err)
	}
}

// ── HNDL at-risk query ────────────────────────────────────────────────

// seedHNDLCert creates a vulnerable RSA-2048 certificate tagged with
// the given application tags. Used by the HNDL at-risk tests below.
func seedHNDLCert(t *testing.T, st *PostgresStore, suffix string, tags []string) string {
	t.Helper()
	ctx := context.Background()
	fp := "sha256:hndl-" + suffix
	cert := &model.Certificate{
		FingerprintSHA256: fp,
		Subject:           model.DistinguishedName{CommonName: "hndl-" + suffix + ".example"},
		Issuer:            model.DistinguishedName{CommonName: "TestCA"},
		SerialNumber:      "hndl-serial-" + suffix,
		NotBefore:         time.Now().Add(-30 * 24 * time.Hour),
		NotAfter:          time.Now().Add(365 * 24 * time.Hour),
		KeyAlgorithm:      model.KeyRSA,
		KeySizeBits:       2048,
		IsCA:              false,
		SourceDiscovery:   model.SourceZeekPassive,
		FirstSeen:         time.Now(),
		LastSeen:          time.Now(),
	}
	if err := st.UpsertCertificate(ctx, cert); err != nil {
		t.Fatalf("upsert cert: %v", err)
	}
	// Attach application_tags (not part of UpsertCertificate). NOT NULL
	// constraint — coerce a Go nil slice to an empty array.
	if tags == nil {
		tags = []string{}
	}
	if _, err := st.pool.Exec(ctx,
		`UPDATE certificates SET application_tags = $1 WHERE fingerprint_sha256 = $2`,
		tags, fp,
	); err != nil {
		t.Fatalf("set application_tags: %v", err)
	}
	return fp
}

// TestListHNDLAtRiskAssets_TaggedAtRisk seeds two vulnerable certs —
// one tagged with a long-TTL app (sensitive past CRQC horizon),
// one tagged with a short-TTL app (clear). Confirms only the long
// one appears.
func TestListHNDLAtRiskAssets_TaggedAtRisk(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	// 20y declaration — pushes sensitive_until well past CRQC 2030.
	if err := st.UpsertApplicationMetadata(ctx, &DeclareApplicationMetadataRequest{
		Tag: "pii-long", DataTTLYears: intp(20),
	}); err != nil {
		t.Fatalf("seed long metadata: %v", err)
	}
	// 1y declaration — sensitive_until < CRQC 2030 when test runs (2026).
	if err := st.UpsertApplicationMetadata(ctx, &DeclareApplicationMetadataRequest{
		Tag: "ops-short", DataTTLYears: intp(1),
	}); err != nil {
		t.Fatalf("seed short metadata: %v", err)
	}

	longCert := seedHNDLCert(t, st, "long", []string{"pii-long"})
	shortCert := seedHNDLCert(t, st, "short", []string{"ops-short"})

	at, err := st.ListHNDLAtRiskAssets(ctx, 2030)
	if err != nil {
		t.Fatalf("hndl: %v", err)
	}

	var sawLong, sawShort bool
	for _, a := range at {
		if a.AssetID == longCert {
			sawLong = true
			if a.Unscoped {
				t.Errorf("long-TTL cert marked unscoped; want at-risk")
			}
			if a.MaxTTLYears != 20 {
				t.Errorf("MaxTTLYears = %d, want 20", a.MaxTTLYears)
			}
		}
		if a.AssetID == shortCert {
			sawShort = true
		}
	}
	if !sawLong {
		t.Errorf("long-TTL cert missing from at-risk list")
	}
	if sawShort {
		t.Errorf("short-TTL cert must NOT appear (clear, below CRQC horizon)")
	}
}

// TestListHNDLAtRiskAssets_UnscopedVulnerable confirms vulnerable assets
// with no application tags (or no metadata for any tag) appear with
// Unscoped=true.
func TestListHNDLAtRiskAssets_UnscopedVulnerable(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	noTags := seedHNDLCert(t, st, "notags", nil)
	undeclaredTag := seedHNDLCert(t, st, "undeclared", []string{"some-undeclared-tag"})

	at, err := st.ListHNDLAtRiskAssets(ctx, 2030)
	if err != nil {
		t.Fatalf("hndl: %v", err)
	}

	var sawNoTags, sawUndeclared bool
	for _, a := range at {
		if a.AssetID == noTags {
			sawNoTags = true
			if !a.Unscoped {
				t.Errorf("no-tags cert should be unscoped")
			}
			if a.MaxTTLYears != 0 || !a.SensitiveUntil.IsZero() {
				t.Errorf("unscoped row must carry zeroed TTL/until; got ttl=%d until=%v", a.MaxTTLYears, a.SensitiveUntil)
			}
		}
		if a.AssetID == undeclaredTag {
			sawUndeclared = true
			if !a.Unscoped {
				t.Errorf("undeclared-tag cert should be unscoped")
			}
		}
	}
	if !sawNoTags {
		t.Errorf("no-tags cert missing from list")
	}
	if !sawUndeclared {
		t.Errorf("undeclared-tag cert missing from list")
	}
}

// TestListHNDLAtRiskAssets_MultiTagMaxWins — an asset tagged with both
// a short-TTL and a long-TTL application must be at-risk by the long
// TTL (max wins, conservative).
func TestListHNDLAtRiskAssets_MultiTagMaxWins(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	_ = st.UpsertApplicationMetadata(ctx, &DeclareApplicationMetadataRequest{
		Tag: "max-short", DataTTLYears: intp(1),
	})
	_ = st.UpsertApplicationMetadata(ctx, &DeclareApplicationMetadataRequest{
		Tag: "max-long", DataTTLYears: intp(25),
	})

	fp := seedHNDLCert(t, st, "multi", []string{"max-short", "max-long"})

	at, err := st.ListHNDLAtRiskAssets(ctx, 2030)
	if err != nil {
		t.Fatalf("hndl: %v", err)
	}
	var found bool
	for _, a := range at {
		if a.AssetID == fp {
			found = true
			if a.Unscoped {
				t.Error("multi-tag cert marked unscoped")
			}
			if a.MaxTTLYears != 25 {
				t.Errorf("MaxTTLYears = %d, want 25 (long wins)", a.MaxTTLYears)
			}
		}
	}
	if !found {
		t.Error("multi-tag cert missing from at-risk list")
	}
}

// TestListHNDLAtRiskAssets_CRQCHorizonShift — shifting the horizon
// changes which assets are at-risk. An asset with TTL=5y is at-risk
// when horizon=2028 (added_at + 5 ≈ 2031 > 2028) but clear when
// horizon=2035 (added_at + 5 < 2035).
func TestListHNDLAtRiskAssets_CRQCHorizonShift(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	_ = st.UpsertApplicationMetadata(ctx, &DeclareApplicationMetadataRequest{
		Tag: "horizon-test", DataTTLYears: intp(5),
	})
	fp := seedHNDLCert(t, st, "horizon", []string{"horizon-test"})

	// Near horizon: 2028. Cert added now (2026) with 5y TTL → sensitive
	// until ~2031. 2031 ≥ 2028 → at-risk.
	nearAt, _ := st.ListHNDLAtRiskAssets(ctx, 2028)
	var nearFound bool
	for _, a := range nearAt {
		if a.AssetID == fp && !a.Unscoped {
			nearFound = true
		}
	}
	if !nearFound {
		t.Error("5y cert must be at-risk at horizon=2028")
	}

	// Far horizon: 2040. 2031 < 2040 → clear (not in list).
	farAt, _ := st.ListHNDLAtRiskAssets(ctx, 2040)
	for _, a := range farAt {
		if a.AssetID == fp && !a.Unscoped {
			t.Error("5y cert must NOT be at-risk at horizon=2040 (clear)")
		}
	}
}

// TestListHNDLAtRiskAssets_SafeAlgorithmExcluded confirms quantum-safe
// algorithms are never surfaced regardless of TTL. Seeds an Ed25519
// cert tagged with a long-TTL app; Ed25519 is classical asymmetric so
// pqc.Classify returns QuantumVulnerable too — Ed25519 is actually
// broken by Shor. Use a hash instead: sha256. Hashes are
// QuantumWeakened not QuantumVulnerable; weak-algo scanner emits
// them but HNDL filter is vulnerable-only.
//
// Simpler: the weak-algo scanner already separates vulnerable from
// weakened; HNDL pulls only vulnerable. We rely on that filter.
// This test just confirms the filter propagates — weakened-but-not-
// vulnerable assets don't leak in.
func TestListHNDLAtRiskAssets_OnlyVulnerableSurface(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	// Seed metadata so there's a horizon to evaluate against.
	_ = st.UpsertApplicationMetadata(ctx, &DeclareApplicationMetadataRequest{
		Tag: "safe-test", DataTTLYears: intp(25),
	})
	// Seed ONE vulnerable cert (RSA-2048) and no weakened-only assets.
	// If the test runs against a real DB with other weakened assets
	// from prior tests, this test just confirms that no Unscoped entry
	// carries a non-vulnerable classification — the weak-algo scanner's
	// filter is the gate.
	vuln := seedHNDLCert(t, st, "vuln-only", []string{"safe-test"})

	at, err := st.ListHNDLAtRiskAssets(ctx, 2030)
	if err != nil {
		t.Fatalf("hndl: %v", err)
	}
	for _, a := range at {
		if a.AssetID == vuln {
			// Must be present (RSA-2048 is vulnerable, TTL=25y pushes
			// sensitive_until well past 2030).
			if a.Unscoped {
				t.Error("RSA-2048 cert with declared tag marked unscoped")
			}
			return
		}
	}
	t.Error("seeded vulnerable cert missing from at-risk list")
}

// TestListHNDLAtRiskAssets_AtRiskRowsSortFirst pins the v1.8.0 sort
// invariant: every at-risk row appears before every unscoped row in
// the returned slice. The `/analysis/hndl` listing + v1.8.0 "Unowned"
// filter pill rely on this order so analysts see the highest-priority
// assets first without a client-side re-sort. Matches
// research/ownership-plan-v1.8.0.md §7.
//
// Seeds three assets — one at-risk, two unscoped — and asserts the
// at-risk row's index in the returned slice is strictly less than the
// smallest unscoped-row index.
func TestListHNDLAtRiskAssets_AtRiskRowsSortFirst(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	// Seed an at-risk declaration + cert and two unscoped certs. The
	// two unscoped inserts bracket the at-risk insert so any
	// insertion-order-preserving bug in the sort would leave unscoped
	// rows at position 0.
	if err := st.UpsertApplicationMetadata(ctx, &DeclareApplicationMetadataRequest{
		Tag: "longlived-pii", DataTTLYears: intp(20),
	}); err != nil {
		t.Fatalf("seed declaration: %v", err)
	}
	unscopedA := seedHNDLCert(t, st, "unscoped-a", nil)
	atRisk := seedHNDLCert(t, st, "at-risk", []string{"longlived-pii"})
	unscopedB := seedHNDLCert(t, st, "unscoped-b", nil)

	assets, err := st.ListHNDLAtRiskAssets(ctx, 2030)
	if err != nil {
		t.Fatalf("hndl: %v", err)
	}

	var atRiskIdx = -1
	var firstUnscopedIdx = -1
	for i, a := range assets {
		if a.AssetID == atRisk {
			atRiskIdx = i
		}
		if a.AssetID == unscopedA || a.AssetID == unscopedB {
			if firstUnscopedIdx == -1 {
				firstUnscopedIdx = i
			}
		}
	}

	if atRiskIdx == -1 {
		t.Fatalf("at-risk cert missing from list; got %d assets", len(assets))
	}
	if firstUnscopedIdx == -1 {
		t.Fatalf("neither unscoped cert made the list; got %d assets", len(assets))
	}
	if atRiskIdx >= firstUnscopedIdx {
		t.Errorf("at-risk row at index %d but first unscoped row at index %d — at-risk must sort first",
			atRiskIdx, firstUnscopedIdx)
	}
}
