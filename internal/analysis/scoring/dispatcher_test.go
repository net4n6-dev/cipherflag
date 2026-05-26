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

package scoring

import (
	"context"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// fakeStore implements the minimum store.CryptoStore surface the
// dispatcher needs. Tests assert on captured inputs.
type fakeStore struct {
	store.CryptoStore // embed interface — unused methods panic if called
	ssh          *model.SSHKey
	lib          *model.CryptoLibrary
	cfg          *model.CryptoConfig
	cert         *model.Certificate
	ep           *model.ProtocolEndpoint
	cves         []model.CryptoLibraryCVE
	savedAsset   []*model.AssetHealthReport
	savedHR      []*model.HealthReport
	saveHRErr    error
	saveAssetErr error
}

func (f *fakeStore) GetSSHKey(_ context.Context, id string) (*model.SSHKey, error) {
	if f.ssh != nil && f.ssh.ID == id {
		return f.ssh, nil
	}
	return nil, nil
}
func (f *fakeStore) GetCryptoLibrary(_ context.Context, id string) (*model.CryptoLibrary, error) {
	if f.lib != nil && f.lib.ID == id {
		return f.lib, nil
	}
	return nil, nil
}
func (f *fakeStore) GetCryptoConfig(_ context.Context, id string) (*model.CryptoConfig, error) {
	if f.cfg != nil && f.cfg.ID == id {
		return f.cfg, nil
	}
	return nil, nil
}
func (f *fakeStore) GetCertificate(_ context.Context, fp string) (*model.Certificate, error) {
	if f.cert != nil && f.cert.FingerprintSHA256 == fp {
		return f.cert, nil
	}
	return nil, nil
}
func (f *fakeStore) SaveAssetHealthReport(_ context.Context, r *model.AssetHealthReport) error {
	f.savedAsset = append(f.savedAsset, r)
	return f.saveAssetErr
}
func (f *fakeStore) SaveHealthReport(_ context.Context, r *model.HealthReport) error {
	f.savedHR = append(f.savedHR, r)
	return f.saveHRErr
}
func (f *fakeStore) GetCryptoLibraryCVEs(_ context.Context, _, _ string) ([]model.CryptoLibraryCVE, error) {
	return f.cves, nil
}
func (f *fakeStore) GetProtocolEndpoint(_ context.Context, id string) (*model.ProtocolEndpoint, error) {
	if f.ep != nil && f.ep.ID == id {
		return f.ep, nil
	}
	return nil, nil
}

func TestDispatcher_SSHKey(t *testing.T) {
	fs := &fakeStore{ssh: &model.SSHKey{ID: "k1", KeyType: "ssh-ed25519", KeySizeBits: 256, FirstSeen: time.Now()}}
	d := NewDispatcher(fs)
	if err := d.ScoreAsset(context.Background(), "ssh_key", "k1"); err != nil {
		t.Fatalf("ScoreAsset: %v", err)
	}
	if len(fs.savedAsset) != 1 {
		t.Fatalf("expected 1 saved asset; got %d", len(fs.savedAsset))
	}
	if fs.savedAsset[0].AssetType != "ssh_key" {
		t.Errorf("AssetType = %s", fs.savedAsset[0].AssetType)
	}
	if fs.savedAsset[0].RuleEngineVersion != CurrentRuleEngineVersion {
		t.Errorf("RuleEngineVersion = %d, want %d", fs.savedAsset[0].RuleEngineVersion, CurrentRuleEngineVersion)
	}
	// 4.3 compliance populated (CE subset: pci_dss_4 is EE-only).
	got := fs.savedAsset[0]
	for _, framework := range []string{
		"nist_800_131a", "fips_140_3", "cnsa_2", "nis2",
	} {
		if v, ok := got.Compliance[framework]; !ok || v == "" {
			t.Errorf("Compliance[%q] missing or empty after scoring", framework)
		}
	}
	// CE-flavor: 4.4 risk-factor population is EE-only — RiskFactors
	// stays empty in the CE dispatcher overlay.
}

func TestDispatcher_UnknownAssetType(t *testing.T) {
	d := NewDispatcher(&fakeStore{})
	err := d.ScoreAsset(context.Background(), "not-a-type", "id")
	if err == nil {
		t.Fatal("expected error for unknown asset type")
	}
}

func TestDispatcher_NilAssetReturnsNil(t *testing.T) {
	d := NewDispatcher(&fakeStore{})
	if err := d.ScoreAsset(context.Background(), "ssh_key", "missing"); err != nil {
		t.Errorf("nil asset should not be an error: %v", err)
	}
}

func TestDispatcher_CertDualWrites(t *testing.T) {
	fs := &fakeStore{cert: &model.Certificate{
		FingerprintSHA256: "abc",
		KeyAlgorithm:      model.KeyAlgorithm("RSA"),
		KeySizeBits:       2048,
		NotBefore:         time.Now().Add(-time.Hour),
		NotAfter:          time.Now().Add(365 * 24 * time.Hour),
	}}
	d := NewDispatcher(fs)
	if err := d.ScoreAsset(context.Background(), "certificate", "abc"); err != nil {
		t.Fatalf("ScoreAsset: %v", err)
	}
	if len(fs.savedAsset) != 1 {
		t.Errorf("expected 1 asset_health_reports write; got %d", len(fs.savedAsset))
	}
	if len(fs.savedHR) != 1 {
		t.Errorf("expected 1 health_reports write (dual-write); got %d", len(fs.savedHR))
	}
	// 4.3 compliance populated (CE subset: pci_dss_4 is EE-only).
	got := fs.savedAsset[0]
	for _, framework := range []string{
		"nist_800_131a", "fips_140_3", "cnsa_2", "nis2",
	} {
		if v, ok := got.Compliance[framework]; !ok || v == "" {
			t.Errorf("Compliance[%q] missing or empty after scoring", framework)
		}
	}
	// CE-flavor: 4.4 risk-factor population is EE-only — RiskFactors
	// stays empty in the CE dispatcher overlay.
}

func TestDispatcher_Library(t *testing.T) {
	fs := &fakeStore{lib: &model.CryptoLibrary{ID: "l1", LibraryName: "openssl", Version: "3.0.8", PQCCapable: true}}
	d := NewDispatcher(fs)
	if err := d.ScoreAsset(context.Background(), "crypto_library", "l1"); err != nil {
		t.Fatalf("ScoreAsset: %v", err)
	}
	if len(fs.savedAsset) != 1 {
		t.Fatalf("expected 1 saved asset; got %d", len(fs.savedAsset))
	}
	// 4.3 compliance populated (CE subset: pci_dss_4 is EE-only).
	got := fs.savedAsset[0]
	for _, framework := range []string{
		"nist_800_131a", "fips_140_3", "cnsa_2", "nis2",
	} {
		if v, ok := got.Compliance[framework]; !ok || v == "" {
			t.Errorf("Compliance[%q] missing or empty after scoring", framework)
		}
	}
	// CE-flavor: 4.4 risk-factor population is EE-only — RiskFactors
	// stays empty in the CE dispatcher overlay.
}

func TestDispatcher_Config(t *testing.T) {
	fs := &fakeStore{cfg: &model.CryptoConfig{ID: "c1", ConfigType: "sshd", Settings: map[string]string{"PasswordAuthentication": "no"}}}
	d := NewDispatcher(fs)
	if err := d.ScoreAsset(context.Background(), "crypto_config", "c1"); err != nil {
		t.Fatalf("ScoreAsset: %v", err)
	}
	if len(fs.savedAsset) != 1 {
		t.Fatalf("expected 1 saved asset; got %d", len(fs.savedAsset))
	}
	// 4.3 compliance populated (CE subset: pci_dss_4 is EE-only).
	got := fs.savedAsset[0]
	for _, framework := range []string{
		"nist_800_131a", "fips_140_3", "cnsa_2", "nis2",
	} {
		if v, ok := got.Compliance[framework]; !ok || v == "" {
			t.Errorf("Compliance[%q] missing or empty after scoring", framework)
		}
	}
	// CE-flavor: 4.4 risk-factor population is EE-only — RiskFactors
	// stays empty in the CE dispatcher overlay.
}

func TestNoopScorer_ReturnsNil(t *testing.T) {
	s := NewNoopScorer()
	for _, at := range []string{"certificate", "ssh_key", "crypto_library", "crypto_config", "unknown"} {
		if err := s.ScoreAsset(context.Background(), at, "id"); err != nil {
			t.Errorf("Noop.ScoreAsset(%s) = %v; want nil", at, err)
		}
	}
}

func TestDispatcher_CallsScoredCallback(t *testing.T) {
	fs := &fakeStore{ssh: &model.SSHKey{ID: "k1", KeyType: "ssh-ed25519", KeySizeBits: 256, FirstSeen: time.Now()}}

	var cbAssetType, cbAssetID string
	called := false
	cb := func(at, id string) {
		cbAssetType = at
		cbAssetID = id
		called = true
	}

	d := NewDispatcher(fs, WithScoredCallback(cb))
	if err := d.ScoreAsset(context.Background(), "ssh_key", "k1"); err != nil {
		t.Fatalf("ScoreAsset: %v", err)
	}
	if !called {
		t.Fatal("ScoredCallback was not called")
	}
	if cbAssetType != "ssh_key" || cbAssetID != "k1" {
		t.Errorf("callback args = (%q, %q), want (ssh_key, k1)", cbAssetType, cbAssetID)
	}
}

func TestDispatcher_NoCallbackNoPanic(t *testing.T) {
	fs := &fakeStore{ssh: &model.SSHKey{ID: "k2", KeyType: "ssh-ed25519", KeySizeBits: 256, FirstSeen: time.Now()}}
	d := NewDispatcher(fs) // no callback option — must not panic
	if err := d.ScoreAsset(context.Background(), "ssh_key", "k2"); err != nil {
		t.Fatalf("ScoreAsset: %v", err)
	}
}

func TestDispatcher_LibraryCVE_FiresLIB001(t *testing.T) {
	fs := &fakeStore{
		lib: &model.CryptoLibrary{ID: "l-cve", LibraryName: "openssl", Version: "1.0.1c", PQCCapable: false},
		cves: []model.CryptoLibraryCVE{
			{LibraryName: "openssl", VersionRange: ">=1.0.1 <1.0.1g", CVEID: "CVE-2014-0160", Severity: "Critical", Description: "Heartbleed"},
		},
	}
	d := NewDispatcher(fs)
	if err := d.ScoreAsset(context.Background(), "crypto_library", "l-cve"); err != nil {
		t.Fatalf("ScoreAsset: %v", err)
	}
	if len(fs.savedAsset) != 1 {
		t.Fatalf("expected 1 saved asset; got %d", len(fs.savedAsset))
	}
	got := fs.savedAsset[0]
	found := false
	for _, f := range got.Findings {
		if f.RuleID == "LIB-001" {
			found = true
			break
		}
	}
	if !found {
		t.Error("LIB-001 not found in dispatcher-scored report with matching critical CVE")
	}
	if got.Grade != string(model.GradeF) {
		t.Errorf("Grade = %s, want F (ImmediateFail from LIB-001)", got.Grade)
	}
}

// CE-flavor: TestDispatcher_Protocol removed. The "crypto_protocol"
// asset type (Layer 4.1c protocol-endpoint scoring with PROTO-001..006
// rules) is EE-only; the CE dispatcher overlay returns
// `unknown asset type "crypto_protocol"`.
