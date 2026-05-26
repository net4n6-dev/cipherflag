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

package cbomimport_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	cbomimport "github.com/net4n6-dev/cipherflag/internal/import/cbom"
	"github.com/net4n6-dev/cipherflag/internal/ingest"
	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
	"github.com/net4n6-dev/cipherflag/internal/testdb"
)

// testStoreForImport opens a Postgres test store via testdb.Require, runs
// migrations, and truncates tables so this test is independent of state
// from other integration tests.
func testStoreForImport(t *testing.T) *store.PostgresStore {
	t.Helper()
	connStr := testdb.Require(t)
	ctx := context.Background()
	st, err := store.NewPostgresStore(ctx, connStr)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// Truncate in dependency order (FKs). Ignore "table doesn't exist" errors
	// so a fresh DB also works.
	for _, table := range []string{
		"asset_provenance",
		"asset_health_reports",
		"certificates",
		"ssh_keys",
		"crypto_libraries",
		"crypto_configs",
		"protocol_endpoints",
		"protocol_observations",
		"hosts",
	} {
		_, _ = st.Pool().Exec(ctx, "TRUNCATE TABLE "+table+" CASCADE")
	}
	return st
}

func TestImport_EndToEnd_RoundTrip(t *testing.T) {
	st := testStoreForImport(t)
	ctx := context.Background()

	// Seed a host so the targeted import has a real target.
	// UpsertHost with an empty ID performs an INSERT and populates host.ID.
	host := &model.Host{
		CanonicalHostname: "integration.host",
		FirstSeen:         time.Now().UTC(),
		LastSeen:          time.Now().UTC(),
	}
	if err := st.UpsertHost(ctx, host); err != nil {
		t.Fatalf("seed host: %v", err)
	}
	hostID := host.ID

	// Build a minimal CBOM with one cert + one ssh key + one library.
	fp := "aaaabbbbccccdddd1111222233334444"
	sshFP := "5555eeeeffff11112222333344445555"
	bom := cdx.NewBOM()
	bom.SpecVersion = cdx.SpecVersion1_6
	bom.SerialNumber = "urn:uuid:integration-import-001"
	components := []cdx.Component{
		{
			Type:   cdx.ComponentTypeCryptographicAsset,
			BOMRef: "cert:" + fp,
			Name:   "integration.cert",
			CryptoProperties: &cdx.CryptoProperties{
				AssetType: cdx.CryptoAssetTypeCertificate,
				CertificateProperties: &cdx.CertificateProperties{
					SubjectName:    "CN=integration.cert",
					IssuerName:     "CN=issuer",
					NotValidBefore: "2024-01-01T00:00:00Z",
					NotValidAfter:  "2026-01-01T00:00:00Z",
				},
			},
		},
		{
			Type:   cdx.ComponentTypeCryptographicAsset,
			BOMRef: "sshkey:" + sshFP,
			Name:   "integration.ssh",
			CryptoProperties: &cdx.CryptoProperties{
				AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
				RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
					Type:         cdx.RelatedCryptoMaterialTypePublicKey,
					AlgorithmRef: "algo:ed25519",
				},
			},
		},
		{Type: cdx.ComponentTypeLibrary, Name: "openssl", Version: "3.0.14", BOMRef: "lib:integration"},
	}
	bom.Components = &components

	var buf bytes.Buffer
	enc := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
	if err := enc.Encode(bom); err != nil {
		t.Fatalf("encode bom: %v", err)
	}
	body := buf.Bytes()

	// Wire up importer with the real UnifiedIngester + store.
	ingester := ingest.NewUnifiedIngester(st)
	importer := cbomimport.NewImporter(ingester)

	// First import: host-targeted.
	res1, err := importer.Import(ctx, bytes.NewReader(body), cbomimport.ImportOptions{HostID: hostID})
	if err != nil {
		t.Fatalf("first import: %v", err)
	}
	if res1.Imported.CertificatesNew != 1 || res1.Imported.SSHKeysNew != 1 || res1.Imported.LibrariesNew != 1 {
		t.Errorf("first import counts wrong: %+v", res1.Imported)
	}

	// Verify cert exists.
	cert, err := st.GetCertificate(ctx, fp)
	if err != nil || cert == nil {
		t.Fatalf("certificate not persisted: err=%v cert=%v", err, cert)
	}

	// Verify provenance row with source=cbom_import.
	provs, err := st.GetProvenance(ctx, "certificate", fp)
	if err != nil {
		t.Fatalf("GetProvenance: %v", err)
	}
	foundImport := false
	for _, p := range provs {
		if p.Source == "cbom_import" {
			foundImport = true
			if p.RawMetadata["bom_serial"] != "urn:uuid:integration-import-001" {
				t.Errorf("provenance raw_metadata bom_serial = %v", p.RawMetadata["bom_serial"])
			}
			if p.RawMetadata["bom_ref"] != "cert:"+fp {
				t.Errorf("provenance raw_metadata bom_ref = %v", p.RawMetadata["bom_ref"])
			}
		}
	}
	if !foundImport {
		t.Errorf("no provenance row with source=cbom_import")
	}

	// Second import: same CBOM — all counts should flip to _Updated.
	res2, err := importer.Import(ctx, bytes.NewReader(body), cbomimport.ImportOptions{HostID: hostID})
	if err != nil {
		t.Fatalf("second import: %v", err)
	}
	if res2.Imported.CertificatesNew != 0 {
		t.Errorf("re-import CertificatesNew = %d, want 0", res2.Imported.CertificatesNew)
	}
	if res2.Imported.CertificatesUpdated != 1 {
		t.Errorf("re-import CertificatesUpdated = %d, want 1", res2.Imported.CertificatesUpdated)
	}
}
