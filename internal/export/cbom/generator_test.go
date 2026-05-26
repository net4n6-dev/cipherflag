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
	"strings"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// fakeGenStore satisfies the store.CryptoStore interface for generator tests.
type fakeGenStore struct {
	store.CryptoStore // embed; unused methods panic if called
	hostIDs    []string
	assetRows  []store.ScopeAssetRow
	certs      map[string]*model.Certificate
	sshKeys    map[string]*model.SSHKey
	libs       map[string]*model.CryptoLibrary
	configs    map[string]*model.CryptoConfig
}

func (f *fakeGenStore) GetHostIDsByPatterns(_ context.Context, _ []string) ([]string, error) {
	return f.hostIDs, nil
}
func (f *fakeGenStore) ListScopeAssets(_ context.Context, _ store.ScopeAssetQuery) ([]store.ScopeAssetRow, error) {
	return f.assetRows, nil
}
func (f *fakeGenStore) GetCertificate(_ context.Context, fp string) (*model.Certificate, error) {
	return f.certs[fp], nil
}
func (f *fakeGenStore) GetSSHKey(_ context.Context, id string) (*model.SSHKey, error) {
	return f.sshKeys[id], nil
}
func (f *fakeGenStore) GetCryptoLibrary(_ context.Context, id string) (*model.CryptoLibrary, error) {
	return f.libs[id], nil
}
func (f *fakeGenStore) GetCryptoConfig(_ context.Context, id string) (*model.CryptoConfig, error) {
	return f.configs[id], nil
}

func healthReport(assetType, assetID string) model.AssetHealthReport {
	return model.AssetHealthReport{
		AssetType: assetType, AssetID: assetID,
		Grade: "B", Score: 70, RiskScore: 20,
		PQCStatus: "safe", ScoredAt: time.Now(),
		Compliance: map[string]string{}, RiskFactors: map[string]int{},
	}
}

func TestGenerate_EmptyScopeReturnsEmptyBOM(t *testing.T) {
	fake := &fakeGenStore{hostIDs: []string{"h1"}, assetRows: nil}
	gen := NewGenerator()
	scope := &Scope{Name: "test", HostIDs: []string{"h1"}}
	bom, err := gen.Generate(context.Background(), fake, scope)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if bom == nil {
		t.Fatal("BOM must not be nil")
	}
	if bom.Components != nil && len(*bom.Components) != 0 {
		t.Errorf("expected 0 components, got %d", len(*bom.Components))
	}
}

func TestGenerate_CertificateComponent(t *testing.T) {
	r := healthReport("certificate", "fp1")
	fake := &fakeGenStore{
		hostIDs: []string{"h1"},
		assetRows: []store.ScopeAssetRow{
			{AssetType: "certificate", AssetID: "fp1", Report: r},
		},
		certs: map[string]*model.Certificate{
			"fp1": {
				FingerprintSHA256:  "fp1",
				Subject:            model.DistinguishedName{CommonName: "test.example.com", Full: "CN=test.example.com"},
				Issuer:             model.DistinguishedName{Full: "CN=CA"},
				NotBefore:          time.Now().Add(-time.Hour),
				NotAfter:           time.Now().Add(365 * 24 * time.Hour),
				SignatureAlgorithm: model.SigSHA256WithRSA,
			},
		},
	}
	gen := NewGenerator()
	bom, err := gen.Generate(context.Background(), fake, &Scope{Name: "s", HostIDs: []string{"h1"}})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if bom.Components == nil || len(*bom.Components) == 0 {
		t.Fatal("expected at least one component")
	}
	found := false
	for _, c := range *bom.Components {
		if c.BOMRef == "cert:fp1" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected cert:fp1 component in BOM")
	}
}

func TestGenerate_AlgorithmDeduplication(t *testing.T) {
	r1 := healthReport("certificate", "fp1")
	r2 := healthReport("certificate", "fp2")
	fake := &fakeGenStore{
		hostIDs: []string{"h1"},
		assetRows: []store.ScopeAssetRow{
			{AssetType: "certificate", AssetID: "fp1", Report: r1},
			{AssetType: "certificate", AssetID: "fp2", Report: r2},
		},
		certs: map[string]*model.Certificate{
			"fp1": {FingerprintSHA256: "fp1", SignatureAlgorithm: model.SigSHA256WithRSA,
				Subject: model.DistinguishedName{Full: "CN=a"}, Issuer: model.DistinguishedName{Full: "CN=CA"},
				NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)},
			"fp2": {FingerprintSHA256: "fp2", SignatureAlgorithm: model.SigSHA256WithRSA,
				Subject: model.DistinguishedName{Full: "CN=b"}, Issuer: model.DistinguishedName{Full: "CN=CA"},
				NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)},
		},
	}
	gen := NewGenerator()
	bom, err := gen.Generate(context.Background(), fake, &Scope{Name: "s", HostIDs: []string{"h1"}})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// Count algo: components
	algoCount := 0
	for _, c := range *bom.Components {
		if strings.HasPrefix(c.BOMRef, "algo:") {
			algoCount++
		}
	}
	// Both certs use SHA256WithRSA — expect exactly 1 algo component for that ref
	if algoCount != 1 {
		t.Errorf("expected exactly 1 algo component for SHA256WithRSA, got %d", algoCount)
	}
}

func TestGenerate_MetadataFields(t *testing.T) {
	fake := &fakeGenStore{hostIDs: []string{"h1"}, assetRows: nil}
	gen := NewGenerator()
	bom, err := gen.Generate(context.Background(), fake, &Scope{Name: "prod", HostIDs: []string{"h1"}})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if bom.Metadata == nil {
		t.Fatal("Metadata must not be nil")
	}
	if bom.Metadata.Timestamp == "" {
		t.Error("Metadata.Timestamp must be set")
	}
	if bom.Metadata.Component == nil || bom.Metadata.Component.Name != "prod" {
		t.Errorf("Metadata.Component.Name = %q, want prod", bom.Metadata.Component.Name)
	}
	if bom.SpecVersion != cdx.SpecVersion1_6 {
		t.Errorf("SpecVersion = %v, want 1.6", bom.SpecVersion)
	}
	if bom.SerialNumber == "" || !strings.HasPrefix(bom.SerialNumber, "urn:uuid:") {
		t.Errorf("SerialNumber = %q, want urn:uuid:... prefix", bom.SerialNumber)
	}
	if bom.Metadata.Tools == nil {
		t.Error("Metadata.Tools must not be nil")
	}
}

func TestGenerate_SSHKeyComponent(t *testing.T) {
	r := healthReport("ssh_key", "key-1")
	fake := &fakeGenStore{
		hostIDs: []string{"h1"},
		assetRows: []store.ScopeAssetRow{
			{AssetType: "ssh_key", AssetID: "key-1", Report: r},
		},
		sshKeys: map[string]*model.SSHKey{
			"key-1": {ID: "key-1", FingerprintSHA256: "fp-key-1",
				KeyType: "ssh-ed25519", KeySizeBits: 256,
				FirstSeen: time.Now(), DiscoveryStatus: "active"},
		},
	}
	gen := NewGenerator()
	bom, err := gen.Generate(context.Background(), fake, &Scope{Name: "s", HostIDs: []string{"h1"}})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	found := false
	for _, c := range *bom.Components {
		if c.BOMRef == "sshkey:fp-key-1" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected sshkey:fp-key-1 component")
	}
}

func TestGenerate_LibraryComponent(t *testing.T) {
	r := healthReport("crypto_library", "lib-1")
	fake := &fakeGenStore{
		hostIDs: []string{"h1"},
		assetRows: []store.ScopeAssetRow{
			{AssetType: "crypto_library", AssetID: "lib-1", Report: r},
		},
		libs: map[string]*model.CryptoLibrary{
			"lib-1": {ID: "lib-1", LibraryName: "openssl", Version: "3.0.8"},
		},
	}
	gen := NewGenerator()
	bom, err := gen.Generate(context.Background(), fake, &Scope{Name: "s", HostIDs: []string{"h1"}})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	found := false
	for _, c := range *bom.Components {
		if c.BOMRef == "lib:lib-1" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected lib:lib-1 component")
	}
}

func TestGenerate_ConfigComponent(t *testing.T) {
	r := healthReport("crypto_config", "cfg-1")
	fake := &fakeGenStore{
		hostIDs: []string{"h1"},
		assetRows: []store.ScopeAssetRow{
			{AssetType: "crypto_config", AssetID: "cfg-1", Report: r},
		},
		configs: map[string]*model.CryptoConfig{
			"cfg-1": {ID: "cfg-1", ConfigType: "sshd", FilePath: "/etc/ssh/sshd_config",
				Settings: map[string]string{}},
		},
	}
	gen := NewGenerator()
	bom, err := gen.Generate(context.Background(), fake, &Scope{Name: "s", HostIDs: []string{"h1"}})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	found := false
	for _, c := range *bom.Components {
		if c.BOMRef == "config:cfg-1" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected config:cfg-1 component")
	}
}
