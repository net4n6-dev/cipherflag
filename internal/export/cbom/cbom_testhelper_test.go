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
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// pkiSeedCBOM is the deterministic PKI test scenario used by cbom integration tests.
//
//	HostA holds CA cert "ca-fp" (self-signed root, is_ca=true, AKI=SKI={0xCA,0xFE})
//	HostB holds leaf cert "leaf-fp" (is_ca=false, AKI={0xCA,0xFE})
//	cert_issuance: leaf-fp→ca-fp via aki_ski_match (attested) — written by
//	              UpsertCertificate's inline resolver.
type pkiSeedCBOM struct {
	HostA  uuid.UUID
	HostB  uuid.UUID
	CAFP   string
	LeafFP string
}

// seedPKIScenarioForCBOM inserts the pkiSeedCBOM scenario and returns the
// populated struct. cert_issuance rows are written automatically by
// UpsertCertificate. Both certs get asset_health_reports so
// ListScopeAssets returns them.
func seedPKIScenarioForCBOM(t *testing.T, ctx context.Context, st *store.PostgresStore) pkiSeedCBOM {
	t.Helper()
	s := pkiSeedCBOM{
		HostA:  uuid.New(),
		HostB:  uuid.New(),
		CAFP:   "cbom-ca-fp",
		LeafFP: "cbom-leaf-fp",
	}

	if _, err := st.Pool().Exec(ctx,
		`INSERT INTO hosts (id, canonical_hostname) VALUES ($1, 'cbom-pki-host-a'), ($2, 'cbom-pki-host-b')`,
		s.HostA, s.HostB); err != nil {
		t.Fatalf("seedPKIScenarioForCBOM: insert hosts: %v", err)
	}

	now := time.Now()
	caModel := &model.Certificate{
		FingerprintSHA256:  s.CAFP,
		Subject:            model.DistinguishedName{CommonName: "CBOM Test Root CA", Full: "CN=CBOM Test Root CA"},
		Issuer:             model.DistinguishedName{CommonName: "CBOM Test Root CA", Full: "CN=CBOM Test Root CA"},
		SerialNumber:       "serial-cbom-ca",
		NotBefore:          now.Add(-24 * time.Hour),
		NotAfter:           now.Add(365 * 24 * time.Hour),
		KeyAlgorithm:       model.KeyRSA,
		KeySizeBits:        4096,
		SignatureAlgorithm: model.SigSHA256WithRSA,
		SourceDiscovery:    model.SourceZeekPassive,
		FirstSeen:          now,
		LastSeen:           now,
		IsCA:               true,
		AuthorityKeyID:     []byte{0xCA, 0xFE},
		SubjectKeyID:       []byte{0xCA, 0xFE},
	}
	if err := st.UpsertCertificate(ctx, caModel); err != nil {
		t.Fatalf("seedPKIScenarioForCBOM: UpsertCertificate CA: %v", err)
	}
	if _, err := st.Pool().Exec(ctx,
		`INSERT INTO asset_provenance (asset_type, asset_id, source, host_id, first_seen, last_seen)
		 VALUES ('certificate', $1, 'test', $2, NOW(), NOW())`,
		s.CAFP, s.HostA); err != nil {
		t.Fatalf("seedPKIScenarioForCBOM: asset_provenance CA: %v", err)
	}
	if err := st.SaveAssetHealthReport(ctx, &model.AssetHealthReport{
		AssetType: "certificate", AssetID: s.CAFP,
		Grade: "A", Score: 90, RiskScore: 5, PQCStatus: "safe",
		ScoredAt:  now, Compliance: map[string]string{}, RiskFactors: map[string]int{},
	}); err != nil {
		t.Fatalf("seedPKIScenarioForCBOM: SaveAssetHealthReport CA: %v", err)
	}

	leafModel := &model.Certificate{
		FingerprintSHA256:  s.LeafFP,
		Subject:            model.DistinguishedName{CommonName: "cbom-leaf.example.com", Full: "CN=cbom-leaf.example.com"},
		Issuer:             model.DistinguishedName{CommonName: "CBOM Test Root CA", Full: "CN=CBOM Test Root CA"},
		SerialNumber:       "serial-cbom-leaf",
		NotBefore:          now.Add(-24 * time.Hour),
		NotAfter:           now.Add(365 * 24 * time.Hour),
		KeyAlgorithm:       model.KeyRSA,
		KeySizeBits:        2048,
		SignatureAlgorithm: model.SigSHA256WithRSA,
		SourceDiscovery:    model.SourceZeekPassive,
		FirstSeen:          now,
		LastSeen:           now,
		IsCA:               false,
		AuthorityKeyID:     []byte{0xCA, 0xFE},
		SubjectKeyID:       []byte{0x1E, 0xAF},
	}
	if err := st.UpsertCertificate(ctx, leafModel); err != nil {
		t.Fatalf("seedPKIScenarioForCBOM: UpsertCertificate leaf: %v", err)
	}
	if _, err := st.Pool().Exec(ctx,
		`INSERT INTO asset_provenance (asset_type, asset_id, source, host_id, first_seen, last_seen)
		 VALUES ('certificate', $1, 'test', $2, NOW(), NOW())`,
		s.LeafFP, s.HostB); err != nil {
		t.Fatalf("seedPKIScenarioForCBOM: asset_provenance leaf: %v", err)
	}
	if err := st.SaveAssetHealthReport(ctx, &model.AssetHealthReport{
		AssetType: "certificate", AssetID: s.LeafFP,
		Grade: "B", Score: 75, RiskScore: 20, PQCStatus: "safe",
		ScoredAt:  now, Compliance: map[string]string{}, RiskFactors: map[string]int{},
	}); err != nil {
		t.Fatalf("seedPKIScenarioForCBOM: SaveAssetHealthReport leaf: %v", err)
	}

	return s
}
