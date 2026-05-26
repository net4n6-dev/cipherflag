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

package cbomimport

import (
	"bytes"
	"context"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/net4n6-dev/cipherflag/internal/ingest"
)

// fakeIngester captures the DiscoveryResult passed in and returns a
// configured summary.
type fakeIngester struct {
	received *ingest.DiscoveryResult
	summary  *ingest.IngestionSummary
	err      error
}

func (f *fakeIngester) Ingest(_ context.Context, r *ingest.DiscoveryResult) (*ingest.IngestionSummary, error) {
	f.received = r
	if f.err != nil {
		return nil, f.err
	}
	if f.summary != nil {
		return f.summary, nil
	}
	return &ingest.IngestionSummary{}, nil
}

func (f *fakeIngester) AttributeAssets(_ context.Context, claims []ingest.OwnershipClaim) (emitted, skipped int, err error) {
	return len(claims), 0, nil
}

func makeBOM(t *testing.T, components []cdx.Component) []byte {
	t.Helper()
	bom := cdx.NewBOM()
	bom.SpecVersion = cdx.SpecVersion1_6
	bom.SerialNumber = "urn:uuid:test-importer"
	bom.Components = &components
	var buf bytes.Buffer
	enc := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
	enc.SetPretty(false)
	if err := enc.Encode(bom); err != nil {
		t.Fatalf("encode: %v", err)
	}
	return buf.Bytes()
}

func TestImport_HostlessCertsOnly(t *testing.T) {
	fi := &fakeIngester{summary: &ingest.IngestionSummary{CertificatesNew: 1}}
	importer := NewImporter(fi)

	body := makeBOM(t, []cdx.Component{
		{
			Type:   cdx.ComponentTypeCryptographicAsset,
			BOMRef: "cert:abc",
			CryptoProperties: &cdx.CryptoProperties{
				AssetType:             cdx.CryptoAssetTypeCertificate,
				CertificateProperties: &cdx.CertificateProperties{SubjectName: "CN=x"},
			},
		},
		{
			Type:   cdx.ComponentTypeCryptographicAsset,
			BOMRef: "sshkey:def",
			CryptoProperties: &cdx.CryptoProperties{
				AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
				RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
					Type:         cdx.RelatedCryptoMaterialTypePublicKey,
					AlgorithmRef: "algo:ed25519",
				},
			},
		},
		{Type: cdx.ComponentTypeLibrary, Name: "openssl", Version: "3.0.14", BOMRef: "lib:x"},
	})

	res, err := importer.Import(context.Background(), bytes.NewReader(body), ImportOptions{})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}

	if res.Source != "cbom_import" {
		t.Errorf("Source = %q, want cbom_import", res.Source)
	}
	if fi.received == nil {
		t.Fatal("ingester not called")
	}
	if !fi.received.SkipHostResolution {
		t.Error("SkipHostResolution should be true")
	}
	if len(fi.received.Certificates) != 1 {
		t.Errorf("Certificates forwarded = %d, want 1", len(fi.received.Certificates))
	}
	if len(fi.received.SSHKeys) != 0 || len(fi.received.Libraries) != 0 {
		t.Errorf("SSH/Library must be skipped in hostless mode, got SSH=%d Lib=%d",
			len(fi.received.SSHKeys), len(fi.received.Libraries))
	}

	hostlessSkip := findSkipCategory(res.Skipped, ReasonNoHostSpecified)
	if hostlessSkip == nil || hostlessSkip.ComponentCount != 2 {
		t.Errorf("expected 2 components skipped with reason no_host_specified, got %+v", hostlessSkip)
	}
}

func TestImport_HostTargetedAllAssets(t *testing.T) {
	fi := &fakeIngester{summary: &ingest.IngestionSummary{
		CertificatesNew: 1, SSHKeysNew: 1, LibrariesNew: 1,
	}}
	importer := NewImporter(fi)

	body := makeBOM(t, []cdx.Component{
		{
			Type:   cdx.ComponentTypeCryptographicAsset,
			BOMRef: "cert:abc",
			CryptoProperties: &cdx.CryptoProperties{
				AssetType:             cdx.CryptoAssetTypeCertificate,
				CertificateProperties: &cdx.CertificateProperties{SubjectName: "CN=x"},
			},
		},
		{
			Type:   cdx.ComponentTypeCryptographicAsset,
			BOMRef: "sshkey:def",
			CryptoProperties: &cdx.CryptoProperties{
				AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
				RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
					Type:         cdx.RelatedCryptoMaterialTypePublicKey,
					AlgorithmRef: "algo:ed25519",
				},
			},
		},
		{Type: cdx.ComponentTypeLibrary, Name: "openssl", Version: "3.0.14"},
	})

	hostID := "host-123"
	res, err := importer.Import(context.Background(), bytes.NewReader(body), ImportOptions{HostID: hostID})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if res.HostID != hostID {
		t.Errorf("HostID = %q, want %q", res.HostID, hostID)
	}
	if fi.received.SourceHostID != hostID {
		t.Errorf("SourceHostID = %q, want %q", fi.received.SourceHostID, hostID)
	}
	if len(fi.received.Certificates) != 1 || len(fi.received.SSHKeys) != 1 || len(fi.received.Libraries) != 1 {
		t.Errorf("expected 1 each, got C=%d SSH=%d L=%d",
			len(fi.received.Certificates), len(fi.received.SSHKeys), len(fi.received.Libraries))
	}
	if hostlessSkip := findSkipCategory(res.Skipped, ReasonNoHostSpecified); hostlessSkip != nil {
		t.Errorf("no host-skip category expected for host-targeted import, got %+v", hostlessSkip)
	}
}

func TestImport_NonCryptoLibrarySkipped(t *testing.T) {
	fi := &fakeIngester{}
	importer := NewImporter(fi)

	body := makeBOM(t, []cdx.Component{
		{Type: cdx.ComponentTypeLibrary, Name: "lodash", Version: "4.17.21"},
	})

	res, err := importer.Import(context.Background(), bytes.NewReader(body), ImportOptions{})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	skip := findSkipCategory(res.Skipped, ReasonNonCryptoLibrary)
	if skip == nil || skip.ComponentCount != 1 {
		t.Errorf("expected 1 component skipped non_crypto_library; got %+v", skip)
	}
}

func TestImport_MalformedBOM(t *testing.T) {
	fi := &fakeIngester{}
	importer := NewImporter(fi)

	_, err := importer.Import(context.Background(), strings.NewReader("not json"), ImportOptions{})
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestImport_CarriesRawMetadata(t *testing.T) {
	fi := &fakeIngester{summary: &ingest.IngestionSummary{CertificatesNew: 1}}
	importer := NewImporter(fi)

	body := makeBOM(t, []cdx.Component{
		{
			Type:   cdx.ComponentTypeCryptographicAsset,
			BOMRef: "cert:mycert",
			CryptoProperties: &cdx.CryptoProperties{
				AssetType:             cdx.CryptoAssetTypeCertificate,
				CertificateProperties: &cdx.CertificateProperties{SubjectName: "CN=x"},
			},
		},
	})

	_, err := importer.Import(context.Background(), bytes.NewReader(body), ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(fi.received.Certificates) != 1 {
		t.Fatalf("expected 1 cert forwarded")
	}
	md := fi.received.Certificates[0].RawMetadata
	if md["bom_ref"] != "cert:mycert" {
		t.Errorf("RawMetadata bom_ref = %v, want cert:mycert", md["bom_ref"])
	}
	if md["bom_serial"] != "urn:uuid:test-importer" {
		t.Errorf("RawMetadata bom_serial = %v", md["bom_serial"])
	}
}

func findSkipCategory(cats []SkippedCategory, reason string) *SkippedCategory {
	for i := range cats {
		if cats[i].Reason == reason {
			return &cats[i]
		}
	}
	return nil
}
