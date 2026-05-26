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

package dedup

import (
	"context"
	"strings"
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

type mockStore struct {
	store.CryptoStore
	certs     map[string]*model.Certificate
	sshKeys   map[string]*model.SSHKey
	libraries map[string]*model.CryptoLibrary
	configs   map[string]*model.CryptoConfig
}

func newMockStore() *mockStore {
	return &mockStore{
		certs:     map[string]*model.Certificate{},
		sshKeys:   map[string]*model.SSHKey{},
		libraries: map[string]*model.CryptoLibrary{},
		configs:   map[string]*model.CryptoConfig{},
	}
}

func (m *mockStore) GetCertificate(ctx context.Context, fp string) (*model.Certificate, error) {
	return m.certs[strings.ToLower(fp)], nil
}

func (m *mockStore) UpsertCertificate(ctx context.Context, cert *model.Certificate) error {
	m.certs[strings.ToLower(cert.FingerprintSHA256)] = cert
	return nil
}

func (m *mockStore) UpsertSSHKey(ctx context.Context, key *model.SSHKey) error {
	k := key.HostID + ":" + strings.ToLower(key.FingerprintSHA256)
	if key.ID == "" {
		key.ID = "key-" + k
	}
	m.sshKeys[k] = key
	return nil
}

func (m *mockStore) UpsertCryptoLibrary(ctx context.Context, lib *model.CryptoLibrary) error {
	k := lib.HostID + ":" + strings.ToLower(lib.LibraryName) + ":" + strings.TrimSpace(lib.Version)
	if lib.ID == "" {
		lib.ID = "lib-" + k
	}
	m.libraries[k] = lib
	return nil
}

func (m *mockStore) UpsertCryptoConfig(ctx context.Context, cfg *model.CryptoConfig) error {
	k := cfg.HostID + ":" + cfg.FilePath
	if cfg.ID == "" {
		cfg.ID = "cfg-" + k
	}
	m.configs[k] = cfg
	return nil
}

func TestDedupCertificate_New(t *testing.T) {
	st := newMockStore()
	d := NewDeduplicator(st)
	ctx := context.Background()

	disc := &CertDiscovery{
		FingerprintSHA256: "AABB1122",
		SubjectCN:         "test.example.com",
		KeyAlgorithm:      "RSA",
		KeySizeBits:       4096,
	}

	assetID, isNew, err := d.DedupCertificate(ctx, "host-1", disc)
	if err != nil {
		t.Fatalf("DedupCertificate: %v", err)
	}
	if !isNew {
		t.Error("expected isNew = true for new cert")
	}
	if assetID == "" {
		t.Error("expected non-empty assetID")
	}
}

func TestDedupCertificate_Existing(t *testing.T) {
	st := newMockStore()
	st.certs["aabb1122"] = &model.Certificate{
		FingerprintSHA256: "aabb1122",
	}
	d := NewDeduplicator(st)
	ctx := context.Background()

	disc := &CertDiscovery{FingerprintSHA256: "AABB1122"}

	_, isNew, err := d.DedupCertificate(ctx, "host-1", disc)
	if err != nil {
		t.Fatalf("DedupCertificate: %v", err)
	}
	if isNew {
		t.Error("expected isNew = false for existing cert")
	}
}

func TestDedupCertificate_CaseInsensitive(t *testing.T) {
	st := newMockStore()
	d := NewDeduplicator(st)
	ctx := context.Background()

	disc1 := &CertDiscovery{FingerprintSHA256: "AAbb1122", SubjectCN: "test", KeyAlgorithm: "RSA", KeySizeBits: 2048}
	disc2 := &CertDiscovery{FingerprintSHA256: "aaBB1122", SubjectCN: "test", KeyAlgorithm: "RSA", KeySizeBits: 2048}

	id1, _, _ := d.DedupCertificate(ctx, "host-1", disc1)
	id2, isNew2, _ := d.DedupCertificate(ctx, "host-2", disc2)

	if id1 != id2 {
		t.Errorf("case-insensitive fingerprints should match: %q vs %q", id1, id2)
	}
	if isNew2 {
		t.Error("second cert with same fingerprint should not be new")
	}
}

func TestDedupSSHKey_New(t *testing.T) {
	st := newMockStore()
	d := NewDeduplicator(st)
	ctx := context.Background()

	disc := &SSHKeyDiscovery{
		KeyType: "ssh-ed25519", FingerprintSHA256: "keyFP123",
		KeySizeBits: 256,
	}

	assetID, isNew, err := d.DedupSSHKey(ctx, "host-1", disc)
	if err != nil {
		t.Fatalf("DedupSSHKey: %v", err)
	}
	if !isNew {
		t.Error("expected isNew = true")
	}
	if assetID == "" {
		t.Error("expected non-empty assetID")
	}
}

func TestDedupLibrary_New(t *testing.T) {
	st := newMockStore()
	d := NewDeduplicator(st)
	ctx := context.Background()

	disc := &LibraryDiscovery{
		LibraryName: "OpenSSL", Version: " 3.0.12 ",
	}

	assetID, isNew, err := d.DedupLibrary(ctx, "host-1", disc)
	if err != nil {
		t.Fatalf("DedupLibrary: %v", err)
	}
	if !isNew {
		t.Error("expected isNew = true")
	}
	if assetID == "" {
		t.Error("expected non-empty assetID")
	}

	// Verify normalization: "OpenSSL" should be stored as "openssl"
	key := "host-1:openssl:3.0.12"
	if _, ok := st.libraries[key]; !ok {
		t.Errorf("expected library at key %q, keys are: %v", key, st.libraries)
	}
}

func TestDedupConfig_New(t *testing.T) {
	st := newMockStore()
	d := NewDeduplicator(st)
	ctx := context.Background()

	disc := &ConfigDiscovery{
		ConfigType: "sshd_config", FilePath: "/etc/ssh/sshd_config",
		Settings: map[string]string{"Protocol": "2"},
	}

	assetID, isNew, err := d.DedupConfig(ctx, "host-1", disc)
	if err != nil {
		t.Fatalf("DedupConfig: %v", err)
	}
	if !isNew {
		t.Error("expected isNew = true")
	}
	if assetID == "" {
		t.Error("expected non-empty assetID")
	}
}

// ssh_comment producer coverage moved to
// internal/ingest/ingester_sshcomment_integration_test.go:TestIngest_SSHComment_EmitsSighting
// in v1.10 Phase 0. DedupSSHKey no longer emits sightings itself.
