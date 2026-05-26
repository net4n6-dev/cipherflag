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

	"github.com/net4n6-dev/cipherflag/internal/model"
)

func seedHost(t *testing.T, st *PostgresStore) *model.Host {
	t.Helper()
	h := &model.Host{
		CanonicalHostname: "test-host.example.com",
		IPAddresses:       []string{"10.0.0.1"},
		DiscoverySources:  []string{"test"},
	}
	if err := st.UpsertHost(context.Background(), h); err != nil {
		t.Fatalf("seedHost: %v", err)
	}
	return h
}

func TestUpsertAndGetSSHKey(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	host := seedHost(t, st)

	key := &model.SSHKey{
		HostID:            host.ID,
		KeyType:           "ssh-ed25519",
		KeySizeBits:       256,
		FingerprintSHA256: "sha256:abc123def456",
		FilePath:          "/home/deploy/.ssh/id_ed25519",
		OwnerUser:         "deploy",
		IsAuthorized:      true,
		IsProtected:       true,
		GrantsRoot:        false,
		Source:            "osquery",
		DiscoveryStatus:   "active",
	}

	if err := st.UpsertSSHKey(ctx, key); err != nil {
		t.Fatalf("UpsertSSHKey: %v", err)
	}
	if key.ID == "" {
		t.Fatal("expected key ID to be populated after upsert")
	}

	got, err := st.GetSSHKey(ctx, key.ID)
	if err != nil {
		t.Fatalf("GetSSHKey: %v", err)
	}
	if got == nil {
		t.Fatal("expected SSH key, got nil")
	}
	if got.KeyType != "ssh-ed25519" {
		t.Errorf("key_type = %q, want ssh-ed25519", got.KeyType)
	}
	if got.FingerprintSHA256 != "sha256:abc123def456" {
		t.Errorf("fingerprint = %q, want sha256:abc123def456", got.FingerprintSHA256)
	}
	if !got.IsAuthorized {
		t.Error("expected is_authorized = true")
	}
	if !got.IsProtected {
		t.Error("expected is_protected = true")
	}
}

func TestUpsertSSHKey_Dedup(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	host := seedHost(t, st)

	key := &model.SSHKey{
		HostID:            host.ID,
		KeyType:           "ssh-rsa",
		KeySizeBits:       4096,
		FingerprintSHA256: "sha256:dedup-test-key",
		Source:            "osquery",
		DiscoveryStatus:   "active",
		IsProtected:       false,
	}
	if err := st.UpsertSSHKey(ctx, key); err != nil {
		t.Fatalf("first UpsertSSHKey: %v", err)
	}
	firstID := key.ID

	// Upsert again with different mutable field
	key2 := &model.SSHKey{
		HostID:            host.ID,
		KeyType:           "ssh-rsa",
		KeySizeBits:       4096,
		FingerprintSHA256: "sha256:dedup-test-key",
		Source:            "osquery",
		DiscoveryStatus:   "active",
		IsProtected:       true,
	}
	if err := st.UpsertSSHKey(ctx, key2); err != nil {
		t.Fatalf("second UpsertSSHKey: %v", err)
	}

	// Should be same row
	got, err := st.GetSSHKey(ctx, firstID)
	if err != nil {
		t.Fatalf("GetSSHKey: %v", err)
	}
	if got == nil {
		t.Fatal("expected SSH key after dedup upsert")
	}
	if !got.IsProtected {
		t.Error("expected is_protected to be updated to true on conflict")
	}
}

func TestGetSSHKey_NotFound(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	got, err := st.GetSSHKey(ctx, "00000000-0000-0000-0000-000000000000")
	if err != nil {
		t.Fatalf("GetSSHKey: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil for missing SSH key, got %+v", got)
	}
}

func TestListSSHKeys(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	host := seedHost(t, st)

	for _, fp := range []string{"key-a", "key-b", "key-c"} {
		k := &model.SSHKey{
			HostID:            host.ID,
			KeyType:           "ssh-ed25519",
			FingerprintSHA256: fp,
			Source:            "osquery",
			DiscoveryStatus:   "active",
		}
		if err := st.UpsertSSHKey(ctx, k); err != nil {
			t.Fatalf("UpsertSSHKey %s: %v", fp, err)
		}
	}

	result, err := st.ListSSHKeys(ctx, SSHKeySearchQuery{HostID: host.ID, Limit: 10})
	if err != nil {
		t.Fatalf("ListSSHKeys: %v", err)
	}
	if result.Total != 3 {
		t.Errorf("total = %d, want 3", result.Total)
	}
	if len(result.Keys) != 3 {
		t.Errorf("keys count = %d, want 3", len(result.Keys))
	}
}

func TestListSSHKeys_Search(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	host := seedHost(t, st)

	rows := []*model.SSHKey{
		{
			HostID: host.ID, KeyType: "ssh-ed25519",
			FingerprintSHA256: "sha256:alpha-fp",
			OwnerUser:         "deploy",
			FilePath:          "/home/deploy/.ssh/id_ed25519",
			Source:            "osquery", DiscoveryStatus: "active",
		},
		{
			HostID: host.ID, KeyType: "ssh-rsa",
			FingerprintSHA256: "sha256:beta-fp",
			OwnerUser:         "admin",
			FilePath:          "/root/.ssh/id_rsa",
			Source:            "osquery", DiscoveryStatus: "active",
		},
		{
			HostID: host.ID, KeyType: "ecdsa-sha2-nistp256",
			FingerprintSHA256: "sha256:gamma-fp",
			OwnerUser:         "deploy",
			FilePath:          "/home/deploy/.ssh/id_ecdsa",
			Source:            "osquery", DiscoveryStatus: "active",
		},
	}
	for _, k := range rows {
		if err := st.UpsertSSHKey(ctx, k); err != nil {
			t.Fatalf("UpsertSSHKey %s: %v", k.FingerprintSHA256, err)
		}
	}

	cases := []struct {
		name   string
		search string
		want   int
	}{
		{"owner match — deploy", "deploy", 2},
		{"key type match — rsa", "rsa", 1},
		{"fingerprint substring — beta", "beta-fp", 1},
		{"path substring — root/.ssh", "/root/.ssh", 1},
		{"case insensitive — DEPLOY", "DEPLOY", 2},
		{"no match", "nonexistent-term", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result, err := st.ListSSHKeys(ctx,
				SSHKeySearchQuery{HostID: host.ID, Search: c.search, Limit: 10})
			if err != nil {
				t.Fatalf("ListSSHKeys: %v", err)
			}
			if result.Total != c.want {
				t.Errorf("total = %d, want %d (rows: %+v)", result.Total, c.want, result.Keys)
			}
		})
	}
}

func TestListSSHKeys_FilterByStatus(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	host := seedHost(t, st)

	active := &model.SSHKey{
		HostID: host.ID, KeyType: "ssh-ed25519", FingerprintSHA256: "active-key",
		Source: "osquery", DiscoveryStatus: "active",
	}
	stale := &model.SSHKey{
		HostID: host.ID, KeyType: "ssh-ed25519", FingerprintSHA256: "stale-key",
		Source: "osquery", DiscoveryStatus: "stale",
	}
	if err := st.UpsertSSHKey(ctx, active); err != nil {
		t.Fatalf("UpsertSSHKey active: %v", err)
	}
	if err := st.UpsertSSHKey(ctx, stale); err != nil {
		t.Fatalf("UpsertSSHKey stale: %v", err)
	}

	result, err := st.ListSSHKeys(ctx, SSHKeySearchQuery{Status: "active", Limit: 10})
	if err != nil {
		t.Fatalf("ListSSHKeys filtered: %v", err)
	}
	if result.Total != 1 {
		t.Errorf("filtered total = %d, want 1", result.Total)
	}
}
