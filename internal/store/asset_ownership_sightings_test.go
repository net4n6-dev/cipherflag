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

	"github.com/net4n6-dev/cipherflag/internal/analysis/pqc"
)

// seedOwnableCert inserts a minimal non-CA certificate row and returns
// its fingerprint (which doubles as asset_id for asset_type='certificate').
// Tests that need weak algorithms populate them via opts.
func seedOwnableCert(t *testing.T, st *PostgresStore, fp string, tags []string, isCA bool, keyAlg string, keyBits int) string {
	t.Helper()
	ctx := context.Background()
	if tags == nil {
		tags = []string{}
	}
	_, err := st.pool.Exec(ctx, `
		INSERT INTO certificates (
			fingerprint_sha256, subject_cn, subject_org, subject_ou,
			not_before, not_after, key_algorithm, key_size_bits, is_ca,
			application_tags
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (fingerprint_sha256) DO UPDATE SET
			subject_cn = EXCLUDED.subject_cn,
			subject_org = EXCLUDED.subject_org,
			application_tags = EXCLUDED.application_tags
	`,
		fp, "test-"+fp, "test-org", "",
		time.Now().Add(-24*time.Hour), time.Now().Add(365*24*time.Hour),
		keyAlg, keyBits, isCA, tags,
	)
	if err != nil {
		t.Fatalf("seed cert %s: %v", fp, err)
	}
	return fp
}

// TestUpsertOwnershipSighting_Idempotent asserts that calling with
// the same (asset_type, asset_id, source, team) tuple merges into
// one row with extended last_seen.
func TestUpsertOwnershipSighting_Idempotent(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	seedOwnableCert(t, st, "fp-idem", nil, false, "RSA", 2048)

	t0 := time.Now()
	for i := 0; i < 3; i++ {
		err := st.UpsertOwnershipSighting(ctx, &OwnershipSighting{
			AssetType: "certificate", AssetID: "fp-idem",
			Team: "payments", Source: "application_metadata", Confidence: "attested",
			FirstSeen: t0, LastSeen: t0.Add(time.Duration(i) * time.Minute),
		})
		if err != nil {
			t.Fatalf("upsert iteration %d: %v", i, err)
		}
	}

	var count int
	if err := st.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM asset_ownership_sightings
		WHERE asset_type = 'certificate' AND asset_id = 'fp-idem'
	`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Errorf("got %d rows, want 1 (idempotent merge)", count)
	}
}

// TestUpsertOwnershipSighting_AutoCreatesTeamSkeleton asserts that
// writing a sighting inserts a slug-only teams row when the team
// isn't registered yet — the §2.9 auto-populate path.
func TestUpsertOwnershipSighting_AutoCreatesTeamSkeleton(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	seedOwnableCert(t, st, "fp-team", nil, false, "RSA", 2048)
	if err := st.UpsertOwnershipSighting(ctx, &OwnershipSighting{
		AssetType: "certificate", AssetID: "fp-team",
		Team: "fresh-team", Source: "operator_stamp", Confidence: "direct",
		FirstSeen: time.Now(), LastSeen: time.Now(),
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	team, err := st.GetTeam(ctx, "fresh-team")
	if err != nil {
		t.Fatalf("get team: %v", err)
	}
	if team == nil {
		t.Fatal("expected team skeleton row, got nil")
	}
	if team.Enriched {
		t.Error("expected skeleton team to report Enriched=false")
	}
}

// TestResolveOwner_PolymorphicAssetTypes smoke-tests the CHECK
// constraint accepts all 7 enum values and the resolver round-trips.
func TestResolveOwner_PolymorphicAssetTypes(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	types := []string{"certificate", "ssh_key", "crypto_library", "crypto_config", "protocol_endpoint", "host", "repository"}
	for _, at := range types {
		assetID := "poly-" + at
		if err := st.UpsertOwnershipSighting(ctx, &OwnershipSighting{
			AssetType: at, AssetID: assetID,
			Team: "poly-team", Source: "operator_stamp", Confidence: "direct",
			FirstSeen: time.Now(), LastSeen: time.Now(),
		}); err != nil {
			t.Fatalf("upsert %s: %v", at, err)
		}
		res, err := st.ResolveOwner(ctx, at, assetID)
		if err != nil {
			t.Fatalf("resolve %s: %v", at, err)
		}
		if res.Unknown {
			t.Errorf("%s: got Unknown=true, want resolved", at)
			continue
		}
		if res.Primary == nil || res.Primary.Team != "poly-team" {
			t.Errorf("%s: Primary=%+v, want team=poly-team", at, res.Primary)
		}
	}
}

// TestResolveOwner_FindingDelegation asserts asset_type='finding'
// delegates to the report's source (asset_type, asset_id) without
// writing a 'finding'-typed row (which would violate the CHECK).
func TestResolveOwner_FindingDelegation(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	seedOwnableCert(t, st, "fp-find", nil, false, "RSA", 2048)
	if err := st.UpsertOwnershipSighting(ctx, &OwnershipSighting{
		AssetType: "certificate", AssetID: "fp-find",
		Team: "owner-of-cert", Source: "application_metadata", Confidence: "attested",
		FirstSeen: time.Now(), LastSeen: time.Now(),
	}); err != nil {
		t.Fatalf("upsert cert sighting: %v", err)
	}

	var reportID string
	err := st.pool.QueryRow(ctx, `
		INSERT INTO asset_health_reports (asset_type, asset_id, grade)
		VALUES ('certificate', 'fp-find', 'F')
		RETURNING id::text
	`).Scan(&reportID)
	if err != nil {
		t.Fatalf("insert health report: %v", err)
	}

	res, err := st.ResolveOwner(ctx, "finding", reportID)
	if err != nil {
		t.Fatalf("resolve finding: %v", err)
	}
	if res.Unknown {
		t.Fatal("finding resolve returned Unknown, expected delegated owner")
	}
	if res.Primary == nil || res.Primary.Team != "owner-of-cert" {
		t.Errorf("Primary=%+v, want team=owner-of-cert", res.Primary)
	}
	if res.AssetType != "finding" || res.AssetID != reportID {
		t.Errorf("resolution identity = (%s, %s), want (finding, %s)", res.AssetType, res.AssetID, reportID)
	}

	// Nothing should have been written with asset_type='finding'.
	var findingRows int
	_ = st.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM asset_ownership_sightings WHERE asset_type = 'finding'
	`).Scan(&findingRows)
	if findingRows != 0 {
		t.Errorf("got %d finding-typed rows, want 0", findingRows)
	}
}

// TestResolveOwner_Unknown asserts an asset with no sightings gets
// Unknown=true and Primary=nil.
func TestResolveOwner_Unknown(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	res, err := st.ResolveOwner(ctx, "certificate", "never-seen")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !res.Unknown || res.Primary != nil {
		t.Errorf("got Unknown=%v Primary=%+v, want Unknown=true Primary=nil", res.Unknown, res.Primary)
	}
}

// TestResolveOwner_TierOrdering asserts Primary lands at the
// strongest tier and Alternatives carries the rest.
func TestResolveOwner_TierOrdering(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	seedOwnableCert(t, st, "fp-tiers", nil, false, "RSA", 2048)

	now := time.Now()
	claims := []OwnershipSighting{
		{AssetType: "certificate", AssetID: "fp-tiers", Team: "via-ssh", Source: "ssh_comment", Confidence: "observed", FirstSeen: now, LastSeen: now},
		{AssetType: "certificate", AssetID: "fp-tiers", Team: "via-subject", Source: "cert_subject", Confidence: "inferred", FirstSeen: now, LastSeen: now},
		{AssetType: "certificate", AssetID: "fp-tiers", Team: "via-agent", Source: "sighting_agent", Confidence: "attested", FirstSeen: now, LastSeen: now},
		{AssetType: "certificate", AssetID: "fp-tiers", Team: "via-stamp", Source: "operator_stamp", Confidence: "direct", FirstSeen: now, LastSeen: now},
	}
	for i := range claims {
		if err := st.UpsertOwnershipSighting(ctx, &claims[i]); err != nil {
			t.Fatalf("upsert claim %d: %v", i, err)
		}
	}

	res, err := st.ResolveOwner(ctx, "certificate", "fp-tiers")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.Primary == nil || res.Primary.Team != "via-stamp" || res.Primary.Confidence != "direct" {
		t.Fatalf("Primary=%+v, want via-stamp/direct", res.Primary)
	}
	if len(res.Alternatives) != 3 {
		t.Errorf("Alternatives count = %d, want 3", len(res.Alternatives))
	}
}

// TestResolveOwner_CoOwners asserts two attested-tier different-team
// sightings surface as co-owners, not as a winner-picked single team.
func TestResolveOwner_CoOwners(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	seedOwnableCert(t, st, "fp-co", nil, false, "RSA", 2048)

	now := time.Now()
	for _, c := range []OwnershipSighting{
		{AssetType: "certificate", AssetID: "fp-co", Team: "payments", Source: "application_metadata", Confidence: "attested", FirstSeen: now, LastSeen: now},
		{AssetType: "certificate", AssetID: "fp-co", Team: "platform", Source: "sighting_agent", Confidence: "attested", FirstSeen: now, LastSeen: now},
	} {
		c := c
		if err := st.UpsertOwnershipSighting(ctx, &c); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}

	res, err := st.ResolveOwner(ctx, "certificate", "fp-co")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(res.CoOwners) != 2 {
		t.Fatalf("CoOwners count = %d, want 2", len(res.CoOwners))
	}
	seen := map[string]bool{}
	for _, c := range res.CoOwners {
		seen[c.Team] = true
	}
	if !seen["payments"] || !seen["platform"] {
		t.Errorf("CoOwners teams = %v, want {payments, platform}", seen)
	}
}

// TestResolveOwner_StampOverridesInferred asserts a direct stamp
// wins even when weaker-tier rows exist for other teams.
func TestResolveOwner_StampOverridesInferred(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	seedOwnableCert(t, st, "fp-stamp", nil, false, "RSA", 2048)

	now := time.Now()
	_ = st.UpsertOwnershipSighting(ctx, &OwnershipSighting{
		AssetType: "certificate", AssetID: "fp-stamp", Team: "wrong-team",
		Source: "cert_subject", Confidence: "inferred", FirstSeen: now, LastSeen: now,
	})
	_ = st.UpsertOwnershipSighting(ctx, &OwnershipSighting{
		AssetType: "certificate", AssetID: "fp-stamp", Team: "correct-team",
		Source: "operator_stamp", Confidence: "direct", FirstSeen: now, LastSeen: now,
	})

	res, _ := st.ResolveOwner(ctx, "certificate", "fp-stamp")
	if res.Primary == nil || res.Primary.Team != "correct-team" {
		t.Errorf("Primary=%+v, want correct-team", res.Primary)
	}
}

// TestDeleteOwnershipStamp_FallsBackToInferred asserts that deleting
// a direct stamp returns the resolver to the weaker-tier fallback.
func TestDeleteOwnershipStamp_FallsBackToInferred(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	seedOwnableCert(t, st, "fp-revoke", nil, false, "RSA", 2048)

	now := time.Now()
	_ = st.UpsertOwnershipSighting(ctx, &OwnershipSighting{
		AssetType: "certificate", AssetID: "fp-revoke", Team: "via-subject",
		Source: "cert_subject", Confidence: "inferred", FirstSeen: now, LastSeen: now,
	})
	_ = st.UpsertOwnershipSighting(ctx, &OwnershipSighting{
		AssetType: "certificate", AssetID: "fp-revoke", Team: "via-stamp",
		Source: "operator_stamp", Confidence: "direct", FirstSeen: now, LastSeen: now,
	})

	if err := st.DeleteOwnershipStamp(ctx, "certificate", "fp-revoke", "via-stamp"); err != nil {
		t.Fatalf("delete stamp: %v", err)
	}
	res, _ := st.ResolveOwner(ctx, "certificate", "fp-revoke")
	if res.Primary == nil || res.Primary.Team != "via-subject" {
		t.Errorf("Primary=%+v, want via-subject (stamp revoked)", res.Primary)
	}
}

// TestResolveOwnerBatch asserts the batch resolver returns a map
// keyed on AssetRef with the same resolution shape as per-call.
func TestResolveOwnerBatch(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	for _, fp := range []string{"fp-b1", "fp-b2", "fp-b3"} {
		seedOwnableCert(t, st, fp, nil, false, "RSA", 2048)
	}
	now := time.Now()
	_ = st.UpsertOwnershipSighting(ctx, &OwnershipSighting{AssetType: "certificate", AssetID: "fp-b1", Team: "team-a", Source: "operator_stamp", Confidence: "direct", FirstSeen: now, LastSeen: now})
	_ = st.UpsertOwnershipSighting(ctx, &OwnershipSighting{AssetType: "certificate", AssetID: "fp-b2", Team: "team-b", Source: "application_metadata", Confidence: "attested", FirstSeen: now, LastSeen: now})
	// fp-b3 deliberately has no sighting.

	refs := []AssetRef{
		{AssetType: "certificate", AssetID: "fp-b1"},
		{AssetType: "certificate", AssetID: "fp-b2"},
		{AssetType: "certificate", AssetID: "fp-b3"},
	}
	out, err := st.ResolveOwnerBatch(ctx, refs)
	if err != nil {
		t.Fatalf("batch resolve: %v", err)
	}
	if out[refs[0]].Primary == nil || out[refs[0]].Primary.Team != "team-a" {
		t.Errorf("b1 resolution wrong: %+v", out[refs[0]])
	}
	if out[refs[1]].Primary == nil || out[refs[1]].Primary.Team != "team-b" {
		t.Errorf("b2 resolution wrong: %+v", out[refs[1]])
	}
	if !out[refs[2]].Unknown {
		t.Errorf("b3 should be Unknown, got %+v", out[refs[2]])
	}
}

// TestBackfillFromApplicationMetadata_OwnerTeamChange asserts the
// option-(a) replacement semantics: when a tag's owner_team flips,
// the old team's sighting for that tag's assets is deleted and a
// new team's sighting is written — no coexistence, no tie-break.
func TestBackfillFromApplicationMetadata_OwnerTeamChange(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	fp := seedOwnableCert(t, st, "fp-rename", []string{"customer-pii"}, false, "RSA", 2048)

	ttl := 20
	req := &DeclareApplicationMetadataRequest{
		Tag: "customer-pii", DataTTLYears: &ttl, OwnerTeam: "payments",
	}
	if err := st.UpsertApplicationMetadata(ctx, req); err != nil {
		t.Fatalf("declare v1: %v", err)
	}
	if _, err := st.BackfillOwnershipFromApplicationMetadata(ctx); err != nil {
		t.Fatalf("backfill v1: %v", err)
	}

	res, _ := st.ResolveOwner(ctx, "certificate", fp)
	if res.Primary == nil || res.Primary.Team != "payments" {
		t.Fatalf("after v1 backfill, Primary=%+v, want payments", res.Primary)
	}

	// Change owner_team — option (a) replacement.
	req.OwnerTeam = "fintech"
	if err := st.UpsertApplicationMetadata(ctx, req); err != nil {
		t.Fatalf("declare v2: %v", err)
	}
	if _, err := st.BackfillOwnershipFromApplicationMetadata(ctx); err != nil {
		t.Fatalf("backfill v2: %v", err)
	}

	// Expect: one application_metadata sighting for this cert, team=fintech.
	rows, _ := st.pool.Query(ctx, `
		SELECT team FROM asset_ownership_sightings
		WHERE asset_type = 'certificate' AND asset_id = $1
		  AND source = 'application_metadata'
	`, fp)
	defer rows.Close()
	teams := []string{}
	for rows.Next() {
		var tm string
		_ = rows.Scan(&tm)
		teams = append(teams, tm)
	}
	if len(teams) != 1 || teams[0] != "fintech" {
		t.Errorf("post-rename application_metadata sightings = %v, want [fintech]", teams)
	}

	res2, _ := st.ResolveOwner(ctx, "certificate", fp)
	if res2.Primary == nil || res2.Primary.Team != "fintech" {
		t.Errorf("post-rename Primary=%+v, want fintech", res2.Primary)
	}
}

// TestBackfillFromCertSubjects_SkipsPlaceholders asserts the
// inference filter refuses to attest low-quality tokens.
func TestBackfillFromCertSubjects_SkipsPlaceholders(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	cases := []struct {
		fp      string
		org, ou string
		wantSkipped bool
	}{
		{"fp-good", "Payments Team", "", false},
		{"fp-short", "US", "", true},
		{"fp-placeholder", "Unknown", "", true},
		{"fp-widgits", "Internet Widgits Pty Ltd", "", true},
		{"fp-empty", "", "", true},
	}
	for _, c := range cases {
		_, err := st.pool.Exec(ctx, `
			INSERT INTO certificates (fingerprint_sha256, subject_cn, subject_org, subject_ou,
				not_before, not_after, key_algorithm, key_size_bits, is_ca)
			VALUES ($1, 'cn', $2, $3, NOW() - INTERVAL '1 day', NOW() + INTERVAL '1 year', 'RSA', 2048, false)
		`, c.fp, c.org, c.ou)
		if err != nil {
			t.Fatalf("seed %s: %v", c.fp, err)
		}
	}

	if _, err := st.BackfillOwnershipFromCertSubjects(ctx); err != nil {
		t.Fatalf("backfill: %v", err)
	}

	for _, c := range cases {
		var cnt int
		_ = st.pool.QueryRow(ctx, `
			SELECT COUNT(*) FROM asset_ownership_sightings
			WHERE asset_type = 'certificate' AND asset_id = $1 AND source = 'cert_subject'
		`, c.fp).Scan(&cnt)
		if c.wantSkipped && cnt != 0 {
			t.Errorf("%s (org=%q): got %d sightings, want 0 (placeholder skipped)", c.fp, c.org, cnt)
		}
		if !c.wantSkipped && cnt == 0 {
			t.Errorf("%s (org=%q): got 0 sightings, want ≥1", c.fp, c.org)
		}
	}
}

// TestBackfillFromCertSubjects_SkipsCACerts asserts is_ca=true certs
// are skipped even when they carry a plausible Organization value.
func TestBackfillFromCertSubjects_SkipsCACerts(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	seedOwnableCert(t, st, "fp-ca", nil, true, "RSA", 4096)
	_, err := st.pool.Exec(ctx, `UPDATE certificates SET subject_org = 'AwesomeCorp' WHERE fingerprint_sha256 = 'fp-ca'`)
	if err != nil {
		t.Fatalf("set org: %v", err)
	}

	if _, err := st.BackfillOwnershipFromCertSubjects(ctx); err != nil {
		t.Fatalf("backfill: %v", err)
	}

	var cnt int
	_ = st.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM asset_ownership_sightings
		WHERE asset_type = 'certificate' AND asset_id = 'fp-ca' AND source = 'cert_subject'
	`).Scan(&cnt)
	if cnt != 0 {
		t.Errorf("got %d sightings for CA cert, want 0", cnt)
	}
}

// TestPruneStaleOwnershipSightings_PreservesDirect asserts the GC
// only removes inferred/observed rows; direct and attested are
// preserved regardless of age.
func TestPruneStaleOwnershipSightings_PreservesDirect(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	seedOwnableCert(t, st, "fp-gc", nil, false, "RSA", 2048)

	old := time.Now().Add(-60 * 24 * time.Hour)
	for _, s := range []OwnershipSighting{
		{AssetType: "certificate", AssetID: "fp-gc", Team: "t-direct", Source: "operator_stamp", Confidence: "direct", FirstSeen: old, LastSeen: old},
		{AssetType: "certificate", AssetID: "fp-gc", Team: "t-inferred", Source: "cert_subject", Confidence: "inferred", FirstSeen: old, LastSeen: old},
		{AssetType: "certificate", AssetID: "fp-gc", Team: "t-observed", Source: "ssh_comment", Confidence: "observed", FirstSeen: old, LastSeen: old},
	} {
		s := s
		if err := st.UpsertOwnershipSighting(ctx, &s); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}

	pruned, err := st.PruneStaleOwnershipSightings(ctx, 30*24*time.Hour)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if pruned != 2 {
		t.Errorf("pruned = %d, want 2 (inferred + observed)", pruned)
	}

	res, _ := st.ResolveOwner(ctx, "certificate", "fp-gc")
	if res.Primary == nil || res.Primary.Team != "t-direct" {
		t.Errorf("after prune Primary=%+v, want t-direct", res.Primary)
	}
}

// TestUpsertOwnershipSighting_RejectsBadCheckValues confirms the DB
// enforces the three CHECK constraints.
func TestUpsertOwnershipSighting_RejectsBadCheckValues(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	seedOwnableCert(t, st, "fp-check", nil, false, "RSA", 2048)

	now := time.Now()
	cases := []OwnershipSighting{
		{AssetType: "invalid_type", AssetID: "fp-check", Team: "t", Source: "operator_stamp", Confidence: "direct", FirstSeen: now, LastSeen: now},
		{AssetType: "certificate", AssetID: "fp-check", Team: "t", Source: "not_a_source", Confidence: "direct", FirstSeen: now, LastSeen: now},
		{AssetType: "certificate", AssetID: "fp-check", Team: "t", Source: "operator_stamp", Confidence: "not_a_tier", FirstSeen: now, LastSeen: now},
	}
	for i, c := range cases {
		c := c
		err := st.UpsertOwnershipSighting(ctx, &c)
		if err == nil {
			t.Errorf("case %d: expected CHECK violation, got nil", i)
		}
	}
}

// TestListUnownedVulnerableAssets_SurfacesVulnerable asserts the
// cross-reference predicate: vulnerable + (unknown OR observed-only).
func TestListUnownedVulnerableAssets_SurfacesVulnerable(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	// Two vulnerable RSA-1024 certs: one attested (owned), one with no sighting.
	seedOwnableCert(t, st, "fp-vuln-owned", nil, false, "RSA", 1024)
	seedOwnableCert(t, st, "fp-vuln-unowned", nil, false, "RSA", 1024)

	now := time.Now()
	_ = st.UpsertOwnershipSighting(ctx, &OwnershipSighting{
		AssetType: "certificate", AssetID: "fp-vuln-owned", Team: "owner",
		Source: "application_metadata", Confidence: "attested",
		FirstSeen: now, LastSeen: now,
	})

	out, err := st.ListUnownedVulnerableAssets(ctx, 2030)
	if err != nil {
		t.Fatalf("list unowned: %v", err)
	}
	foundUnowned, foundOwned := false, false
	for _, r := range out {
		if r.AssetID == "fp-vuln-owned" {
			foundOwned = true
		}
		if r.AssetID == "fp-vuln-unowned" {
			foundUnowned = true
			if r.Classification != pqc.QuantumVulnerable {
				t.Errorf("unowned classification = %v, want QuantumVulnerable", r.Classification)
			}
		}
	}
	if !foundUnowned {
		t.Error("fp-vuln-unowned missing from unowned list")
	}
	if foundOwned {
		t.Error("fp-vuln-owned surfaced in unowned list (should be filtered out)")
	}
}

func TestSlugifyTeam(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"canonical", "Payments Team", "payments-team"},
		{"empty", "", ""},
		{"all-spaces", "   ", ""},
		{"too-short-after-normalise", "x.", ""},
		{"unicode-dropped", "café", "caf"},
		{"collapses-dashes", "a---b", "a-b"},
		{"trims-leading-trailing", "--abc--", "abc"},
		{"underscore-and-dot", "team_a.b", "team-a-b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SlugifyTeam(tc.in)
			if got != tc.want {
				t.Errorf("SlugifyTeam(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
