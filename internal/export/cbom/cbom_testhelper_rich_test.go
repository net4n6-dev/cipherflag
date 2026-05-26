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

package cbom

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// pkiSeedCBOMRich is the rich PKI fixture used by the L4-E golden suite.
// Composes 8 certs, 3 hosts, multi-host observations, all four library-link
// methods, app-scope mapping (app-1 claims leaf-1/leaf-2; app-2 negative
// space), and repo-scope mapping (repo-1 claims leaf-1; repo-2 negative
// space). Designed so a single seed produces meaningful diffs against all
// three Generate* outputs.
//
// All time-bearing values are derived from `now`. FirstSeen/LastSeen/ScoredAt
// fields land in the BOM at scrubbed JSON paths (see scrubVolatileFields
// rule list) so they don't need to be stable across runs. But cert
// NotBefore/NotAfter serialise into cryptoProperties.certificateProperties.
// notValidBefore/notValidAfter — NOT in the scrub list. Those bytes flow
// into the JCS-canonicalised, then JSF-signed, golden output, so `now`
// MUST be a fixed timestamp or every run produces a different golden and
// the signature bytes drift. The pinned value (2026-05-16 12:00 UTC)
// keeps the "expired by -10d" / "valid for +60d" relative offsets in the
// per-cert blocks below meaningful while making the resulting validity
// timestamps deterministic.
//
// Spec: docs/superpowers/specs/2026-05-16-l4-e-cbom-golden-suite-design.md §2.
type pkiSeedCBOMRich struct {
	HostA, HostB, HostC uuid.UUID

	CA1FP, Inter1FP                string
	Leaf1FP, Leaf2FP, Leaf3FP      string
	ShadowLeaf1FP, ShadowIssuer1FP string
	WeakLeaf1FP                    string

	App1Tag, App2Tag string
	Repo1ID, Repo2ID string
}

func seedPKIScenarioForCBOMRich(t *testing.T, ctx context.Context, st *store.PostgresStore) pkiSeedCBOMRich {
	t.Helper()

	s := pkiSeedCBOMRich{
		HostA: uuid.New(), HostB: uuid.New(), HostC: uuid.New(),

		CA1FP:           "cbom-rich-ca-1",
		Inter1FP:        "cbom-rich-inter-1",
		Leaf1FP:         "cbom-rich-leaf-1",
		Leaf2FP:         "cbom-rich-leaf-2",
		Leaf3FP:         "cbom-rich-leaf-3-expired",
		ShadowLeaf1FP:   "cbom-rich-shadow-leaf-1",
		ShadowIssuer1FP: "cbom-rich-shadow-issuer-1",
		WeakLeaf1FP:     "cbom-rich-weak-leaf-1",

		App1Tag: "app-1", App2Tag: "app-2",
		Repo1ID: "repo-1", Repo2ID: "repo-2",
	}

	// Hosts
	if _, err := st.Pool().Exec(ctx, `
		INSERT INTO hosts (id, canonical_hostname) VALUES
			($1, 'cbom-rich-host-a'),
			($2, 'cbom-rich-host-b'),
			($3, 'cbom-rich-host-c')
	`, s.HostA, s.HostB, s.HostC); err != nil {
		t.Fatalf("seedPKIScenarioForCBOMRich: insert hosts: %v", err)
	}

	// Pinned reference time — see pkiSeedCBOMRich doc. UTC is required so
	// the serialised timestamps don't drift across DST transitions or the
	// developer's local timezone.
	now := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)

	// Note: AKI/SKI bytes are chosen so cert_issuance resolution links the
	// chain via aki_ski_match: ca-1 (SKI=A1A1) ← inter-1 (AKI=A1A1, SKI=B2B2)
	// ← leaf-1/leaf-2/leaf-3/weak-leaf-1 (AKI=B2B2). shadow-issuer-1 and
	// shadow-leaf-1 form a fully-resolved sub-chain (AKI=SKI=DEAD) that
	// is disconnected from the main hierarchy — exercising the orphan-CA
	// BOM emission path (the sub-chain has no dependsOn edge back to
	// ca-1/inter-1, so shadow-issuer-1 surfaces as a top-level component).
	// weak-leaf-1 also exercises the weak-algo/weak-key surface.

	// ca-1: self-signed root, RSA-4096, NotAfter +4 years
	caModel := &model.Certificate{
		FingerprintSHA256:  s.CA1FP,
		Subject:            model.DistinguishedName{CommonName: "CBOM Rich Root CA", Full: "CN=CBOM Rich Root CA"},
		Issuer:             model.DistinguishedName{CommonName: "CBOM Rich Root CA", Full: "CN=CBOM Rich Root CA"},
		SerialNumber:       "serial-rich-ca-1",
		NotBefore:          now.Add(-720 * 24 * time.Hour),
		NotAfter:           now.Add(4 * 365 * 24 * time.Hour),
		KeyAlgorithm:       model.KeyRSA,
		KeySizeBits:        4096,
		SignatureAlgorithm: model.SigSHA256WithRSA,
		SourceDiscovery:    model.SourceZeekPassive,
		FirstSeen:          now, LastSeen: now,
		IsCA:           true,
		AuthorityKeyID: []byte{0xA1, 0xA1},
		SubjectKeyID:   []byte{0xA1, 0xA1},
	}
	if err := st.UpsertCertificate(ctx, caModel); err != nil {
		t.Fatalf("seedPKIScenarioForCBOMRich: ca-1: %v", err)
	}

	// inter-1: ECDSA-P256, SHA-384, NotAfter +2 years
	interModel := &model.Certificate{
		FingerprintSHA256:  s.Inter1FP,
		Subject:            model.DistinguishedName{CommonName: "CBOM Rich Intermediate", Full: "CN=CBOM Rich Intermediate"},
		Issuer:             model.DistinguishedName{CommonName: "CBOM Rich Root CA", Full: "CN=CBOM Rich Root CA"},
		SerialNumber:       "serial-rich-inter-1",
		NotBefore:          now.Add(-365 * 24 * time.Hour),
		NotAfter:           now.Add(2 * 365 * 24 * time.Hour),
		KeyAlgorithm:       model.KeyECDSA,
		KeySizeBits:        256,
		SignatureAlgorithm: model.SigECDSAWithSHA384,
		SourceDiscovery:    model.SourceZeekPassive,
		FirstSeen:          now, LastSeen: now,
		IsCA:           true,
		AuthorityKeyID: []byte{0xA1, 0xA1},
		SubjectKeyID:   []byte{0xB2, 0xB2},
	}
	if err := st.UpsertCertificate(ctx, interModel); err != nil {
		t.Fatalf("seedPKIScenarioForCBOMRich: inter-1: %v", err)
	}

	// leaf-1: RSA-2048, SHA-256, NotAfter +60d
	leaf1 := &model.Certificate{
		FingerprintSHA256:  s.Leaf1FP,
		Subject:            model.DistinguishedName{CommonName: "leaf-1.example.com", Full: "CN=leaf-1.example.com"},
		Issuer:             model.DistinguishedName{CommonName: "CBOM Rich Intermediate", Full: "CN=CBOM Rich Intermediate"},
		SerialNumber:       "serial-rich-leaf-1",
		NotBefore:          now.Add(-24 * time.Hour),
		NotAfter:           now.Add(60 * 24 * time.Hour),
		KeyAlgorithm:       model.KeyRSA,
		KeySizeBits:        2048,
		SignatureAlgorithm: model.SigSHA256WithRSA,
		SourceDiscovery:    model.SourceZeekPassive,
		FirstSeen:          now, LastSeen: now,
		IsCA:           false,
		AuthorityKeyID: []byte{0xB2, 0xB2},
		SubjectKeyID:   []byte{0xC3, 0xC3},
	}
	if err := st.UpsertCertificate(ctx, leaf1); err != nil {
		t.Fatalf("seedPKIScenarioForCBOMRich: leaf-1: %v", err)
	}

	// leaf-2: Ed25519, EdDSA, NotAfter +400d
	// Note: model constant is SigEd25519Sig (not SigEd25519); see
	// internal/model/certificate.go:23.
	leaf2 := &model.Certificate{
		FingerprintSHA256:  s.Leaf2FP,
		Subject:            model.DistinguishedName{CommonName: "leaf-2.example.com", Full: "CN=leaf-2.example.com"},
		Issuer:             model.DistinguishedName{CommonName: "CBOM Rich Intermediate", Full: "CN=CBOM Rich Intermediate"},
		SerialNumber:       "serial-rich-leaf-2",
		NotBefore:          now.Add(-24 * time.Hour),
		NotAfter:           now.Add(400 * 24 * time.Hour),
		KeyAlgorithm:       model.KeyEd25519,
		KeySizeBits:        256,
		SignatureAlgorithm: model.SigEd25519Sig,
		SourceDiscovery:    model.SourceZeekPassive,
		FirstSeen:          now, LastSeen: now,
		IsCA:           false,
		AuthorityKeyID: []byte{0xB2, 0xB2},
		SubjectKeyID:   []byte{0xC4, 0xC4},
	}
	if err := st.UpsertCertificate(ctx, leaf2); err != nil {
		t.Fatalf("seedPKIScenarioForCBOMRich: leaf-2: %v", err)
	}

	// leaf-3: RSA-2048, SHA-256, EXPIRED (-10d)
	leaf3 := &model.Certificate{
		FingerprintSHA256:  s.Leaf3FP,
		Subject:            model.DistinguishedName{CommonName: "leaf-3.example.com", Full: "CN=leaf-3.example.com"},
		Issuer:             model.DistinguishedName{CommonName: "CBOM Rich Intermediate", Full: "CN=CBOM Rich Intermediate"},
		SerialNumber:       "serial-rich-leaf-3",
		NotBefore:          now.Add(-400 * 24 * time.Hour),
		NotAfter:           now.Add(-10 * 24 * time.Hour),
		KeyAlgorithm:       model.KeyRSA,
		KeySizeBits:        2048,
		SignatureAlgorithm: model.SigSHA256WithRSA,
		SourceDiscovery:    model.SourceZeekPassive,
		FirstSeen:          now, LastSeen: now,
		IsCA:           false,
		AuthorityKeyID: []byte{0xB2, 0xB2},
		SubjectKeyID:   []byte{0xC5, 0xC5},
	}
	if err := st.UpsertCertificate(ctx, leaf3); err != nil {
		t.Fatalf("seedPKIScenarioForCBOMRich: leaf-3: %v", err)
	}

	// shadow-issuer-1: orphan CA matching shadow-leaf-1.AKI=DEAD
	shadowIssuer := &model.Certificate{
		FingerprintSHA256:  s.ShadowIssuer1FP,
		Subject:            model.DistinguishedName{CommonName: "Shadow Issuer", Full: "CN=Shadow Issuer"},
		Issuer:             model.DistinguishedName{CommonName: "Shadow Issuer", Full: "CN=Shadow Issuer"},
		SerialNumber:       "serial-rich-shadow-issuer",
		NotBefore:          now.Add(-365 * 24 * time.Hour),
		NotAfter:           now.Add(365 * 24 * time.Hour),
		KeyAlgorithm:       model.KeyRSA,
		KeySizeBits:        2048,
		SignatureAlgorithm: model.SigSHA256WithRSA,
		SourceDiscovery:    model.SourceZeekPassive,
		FirstSeen:          now, LastSeen: now,
		IsCA:           true,
		AuthorityKeyID: []byte{0xDE, 0xAD},
		SubjectKeyID:   []byte{0xDE, 0xAD},
	}
	if err := st.UpsertCertificate(ctx, shadowIssuer); err != nil {
		t.Fatalf("seedPKIScenarioForCBOMRich: shadow-issuer-1: %v", err)
	}

	// shadow-leaf-1: RSA-2048, issued by Shadow Issuer
	shadowLeaf := &model.Certificate{
		FingerprintSHA256:  s.ShadowLeaf1FP,
		Subject:            model.DistinguishedName{CommonName: "shadow.example.com", Full: "CN=shadow.example.com"},
		Issuer:             model.DistinguishedName{CommonName: "Shadow Issuer", Full: "CN=Shadow Issuer"},
		SerialNumber:       "serial-rich-shadow-leaf",
		NotBefore:          now.Add(-24 * time.Hour),
		NotAfter:           now.Add(180 * 24 * time.Hour),
		KeyAlgorithm:       model.KeyRSA,
		KeySizeBits:        2048,
		SignatureAlgorithm: model.SigSHA256WithRSA,
		SourceDiscovery:    model.SourceZeekPassive,
		FirstSeen:          now, LastSeen: now,
		IsCA:           false,
		AuthorityKeyID: []byte{0xDE, 0xAD},
		SubjectKeyID:   []byte{0xC6, 0xC6},
	}
	if err := st.UpsertCertificate(ctx, shadowLeaf); err != nil {
		t.Fatalf("seedPKIScenarioForCBOMRich: shadow-leaf-1: %v", err)
	}

	// weak-leaf-1: RSA-1024 + SHA-1, hangs off inter-1
	weakLeaf := &model.Certificate{
		FingerprintSHA256:  s.WeakLeaf1FP,
		Subject:            model.DistinguishedName{CommonName: "weak.example.com", Full: "CN=weak.example.com"},
		Issuer:             model.DistinguishedName{CommonName: "CBOM Rich Intermediate", Full: "CN=CBOM Rich Intermediate"},
		SerialNumber:       "serial-rich-weak-leaf",
		NotBefore:          now.Add(-24 * time.Hour),
		NotAfter:           now.Add(180 * 24 * time.Hour),
		KeyAlgorithm:       model.KeyRSA,
		KeySizeBits:        1024,
		SignatureAlgorithm: model.SigSHA1WithRSA,
		SourceDiscovery:    model.SourceZeekPassive,
		FirstSeen:          now, LastSeen: now,
		IsCA:           false,
		AuthorityKeyID: []byte{0xB2, 0xB2},
		SubjectKeyID:   []byte{0xC7, 0xC7},
	}
	if err := st.UpsertCertificate(ctx, weakLeaf); err != nil {
		t.Fatalf("seedPKIScenarioForCBOMRich: weak-leaf-1: %v", err)
	}

	// asset_provenance (cert observed on host) — same pattern as
	// seedPKIScenarioForCBOM, one INSERT per (cert, host) tuple.
	provenanceTuples := []struct {
		fp   string
		host uuid.UUID
	}{
		{s.CA1FP, s.HostA},         // ca-1 observed on host-a (chain serve)
		{s.Inter1FP, s.HostA},      // inter-1 observed on host-a
		{s.Leaf1FP, s.HostA},       // leaf-1 multi-host
		{s.Leaf1FP, s.HostB},       //
		{s.Leaf2FP, s.HostA},       //
		{s.Leaf3FP, s.HostC},       // expired still deployed
		{s.ShadowLeaf1FP, s.HostB}, // shadow reach
		{s.WeakLeaf1FP, s.HostC},   // weak reach
	}
	for _, p := range provenanceTuples {
		if _, err := st.Pool().Exec(ctx,
			`INSERT INTO asset_provenance (asset_type, asset_id, source, host_id, first_seen, last_seen)
			 VALUES ('certificate', $1, 'test', $2, NOW(), NOW())`,
			p.fp, p.host); err != nil {
			t.Fatalf("seedPKIScenarioForCBOMRich: asset_provenance %s/%v: %v", p.fp, p.host, err)
		}
	}

	// Health reports (one per cert; 8 total)
	healthRows := []model.AssetHealthReport{
		{AssetType: "certificate", AssetID: s.CA1FP, Grade: "A", Score: 92, RiskScore: 4, PQCStatus: "safe", ScoredAt: now, Compliance: map[string]string{}, RiskFactors: map[string]int{}},
		{AssetType: "certificate", AssetID: s.Inter1FP, Grade: "A", Score: 88, RiskScore: 6, PQCStatus: "safe", ScoredAt: now, Compliance: map[string]string{}, RiskFactors: map[string]int{}},
		{AssetType: "certificate", AssetID: s.Leaf1FP, Grade: "B", Score: 78, RiskScore: 20, PQCStatus: "safe", ScoredAt: now, Compliance: map[string]string{}, RiskFactors: map[string]int{}},
		{AssetType: "certificate", AssetID: s.Leaf2FP, Grade: "A", Score: 85, RiskScore: 10, PQCStatus: "safe", ScoredAt: now, Compliance: map[string]string{}, RiskFactors: map[string]int{}},
		{AssetType: "certificate", AssetID: s.Leaf3FP, Grade: "D", Score: 45, RiskScore: 70, PQCStatus: "safe", ScoredAt: now, Compliance: map[string]string{}, RiskFactors: map[string]int{"expired": 1}},
		{AssetType: "certificate", AssetID: s.ShadowIssuer1FP, Grade: "C", Score: 55, RiskScore: 60, PQCStatus: "safe", ScoredAt: now, Compliance: map[string]string{}, RiskFactors: map[string]int{"shadow_ca": 1}},
		{AssetType: "certificate", AssetID: s.ShadowLeaf1FP, Grade: "C", Score: 58, RiskScore: 55, PQCStatus: "safe", ScoredAt: now, Compliance: map[string]string{}, RiskFactors: map[string]int{"shadow_ca": 1}},
		{AssetType: "certificate", AssetID: s.WeakLeaf1FP, Grade: "F", Score: 30, RiskScore: 95, PQCStatus: "vulnerable", ScoredAt: now, Compliance: map[string]string{}, RiskFactors: map[string]int{"weak_key": 1, "weak_signature": 1}},
	}
	for _, h := range healthRows {
		if err := st.SaveAssetHealthReport(ctx, &h); err != nil {
			t.Fatalf("seedPKIScenarioForCBOMRich: health %s: %v", h.AssetID, err)
		}
	}

	// App scope: app-1 claims leaf-1, leaf-2; app-2 claims weak-leaf-1
	// (negative-space — must NOT appear in app-1 golden).
	appAssignments := []struct {
		fp  string
		tag string
	}{
		{s.Leaf1FP, s.App1Tag},
		{s.Leaf2FP, s.App1Tag},
		{s.WeakLeaf1FP, s.App2Tag},
	}
	for _, a := range appAssignments {
		seedAppCertAssignment(t, ctx, st, a.fp, a.tag)
	}

	// Repo scope: repo-1 ← leaf-1 (positive); repo-2 ← leaf-2 (negative space).
	// The fp argument is a hint to choose B3 algorithm content; the
	// underlying ListRepositoryFindings query is keyed on repoID alone.
	seedRepoFinding(t, ctx, st, s.Repo1ID, s.Leaf1FP)
	seedRepoFinding(t, ctx, st, s.Repo2ID, s.Leaf2FP)

	return s
}

// seedAppCertAssignment links a certificate to an application tag by
// appending the tag to certificates.application_tags. This is the
// minimum-viable application surface introduced in migration 021
// (internal/store/migrations/021_application_tags.sql:15). The
// ListApplicationScopeAssets query reads `$1 = ANY(application_tags)`
// from the certificates table (internal/store/cbom_store.go:247) so this
// is the row source that satisfies it.
func seedAppCertAssignment(t *testing.T, ctx context.Context, st *store.PostgresStore, fp, tag string) {
	t.Helper()
	if _, err := st.Pool().Exec(ctx,
		`UPDATE certificates
		    SET application_tags = array_append(application_tags, $2)
		  WHERE fingerprint_sha256 = $1
		    AND NOT ($2 = ANY(application_tags))`,
		fp, tag); err != nil {
		t.Fatalf("seedAppCertAssignment(%s,%s): %v", fp, tag, err)
	}
}

// seedRepoFinding writes one repository asset_health_reports row whose
// JSONB findings array contains a B3 algorithm finding. The fingerprint
// argument feeds into the rule_id / path / scan_id so the two repos
// produce distinguishable component sets without depending on the cert
// table (the findings JSONB is the sole source consulted by
// ListRepositoryFindings — see internal/store/repo_findings.go:24).
//
// Schema notes:
//   - asset_health_reports has no FK to repositories (asset_id is TEXT;
//     see internal/store/migrations/006_crypto_assets.sql).
//   - The findings JSONB shape is the scanner wire format documented in
//     internal/scanner/pipeline/pipeline_e2e_test.go:238-272 (rule_id,
//     severity, bucket, path, detected_by[], confidence, scan_id) plus
//     the cbom sub-object (algorithm, evidence_occurrences) consulted by
//     findingsToAlgoComponents (internal/export/cbom/repo_generator.go).
//   - RawFindings is the documented escape hatch for callers that need a
//     richer JSONB shape than HealthFinding can represent
//     (internal/model/asset_health.go:20-27).
//
// Algorithm choice mirrors the linked cert: leaf-1 (RSA/SHA-256) → "sha256";
// leaf-2 (Ed25519) → "ed25519". The negative-space property assertion in
// later tasks asserts repo-1's BOM contains the leaf-1-flavoured component
// and repo-2's BOM does NOT.
func seedRepoFinding(t *testing.T, ctx context.Context, st *store.PostgresStore, repoID, fp string) {
	t.Helper()

	// Pick a representative algorithm name based on the linked cert.
	algo := "sha256"
	switch fp {
	case "cbom-rich-leaf-2":
		algo = "ed25519"
	case "cbom-rich-leaf-3-expired":
		algo = "sha256"
	case "cbom-rich-weak-leaf-1":
		algo = "sha1"
	}

	rawJSON := fmt.Appendf(nil, `[
		{
			"rule_id":     "CBOM-RICH-B3-%s",
			"severity":    "Medium",
			"bucket":      "B3",
			"path":        "crypto/%s.go",
			"detected_by": ["det:rich-b3"],
			"confidence":  1.0,
			"scan_id":     "scan-rich-%s",
			"cbom": {
				"algorithm": "%s",
				"evidence_occurrences": [
					{"path": "crypto/%s.go", "line": 1}
				]
			}
		}
	]`, algo, algo, repoID, algo, algo)

	report := &model.AssetHealthReport{
		AssetType:   "repository",
		AssetID:     repoID,
		Grade:       "B",
		Score:       70,
		RiskScore:   30,
		PQCStatus:   "unknown",
		ScoredAt:    time.Now(),
		Compliance:  map[string]string{},
		RiskFactors: map[string]int{},
		RawFindings: rawJSON,
	}
	if err := st.SaveAssetHealthReport(ctx, report); err != nil {
		t.Fatalf("seedRepoFinding(%s,%s): %v", repoID, fp, err)
	}
}
