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

	"github.com/net4n6-dev/cipherflag/internal/model"
)

func TestMarkStaleAssets_CycleBased(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	host := seedHost(t, st)

	_, err := st.pool.Exec(ctx, `
		INSERT INTO ssh_keys (host_id, key_type, fingerprint_sha256, source, discovery_status, last_seen)
		VALUES ($1, 'ssh-ed25519', 'stale-key-fp', 'osquery', 'active', $2)
	`, host.ID, time.Now().Add(-10*24*time.Hour))
	if err != nil {
		t.Fatalf("insert stale key: %v", err)
	}

	freshKey := &model.SSHKey{
		HostID: host.ID, KeyType: "ssh-ed25519", FingerprintSHA256: "fresh-key-fp",
		Source: "osquery", DiscoveryStatus: "active",
	}
	if err := st.UpsertSSHKey(ctx, freshKey); err != nil {
		t.Fatalf("insert fresh key: %v", err)
	}

	cfg := AttritionConfig{
		CycleStaleThreshold:   3,
		CycleRemovedThreshold: 7,
		NetworkStaleDays:      7,
		NetworkRemovedDays:    30,
		CycleBasedSources:    []string{"osquery", "agent"},
		NetworkBasedSources:  []string{"zeek_passive", "active_scan"},
	}

	summary, err := st.MarkStaleAssets(ctx, cfg)
	if err != nil {
		t.Fatalf("MarkStaleAssets: %v", err)
	}
	if summary.MarkedStale == 0 {
		t.Error("expected at least 1 asset marked stale")
	}
}

func TestMarkStaleAssets_NetworkBased(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	host := seedHost(t, st)

	_, err := st.pool.Exec(ctx, `
		INSERT INTO crypto_libraries (host_id, library_name, version, source, discovery_status, last_seen)
		VALUES ($1, 'openssl', '3.0.12', 'zeek_passive', 'active', $2)
	`, host.ID, time.Now().Add(-15*24*time.Hour))
	if err != nil {
		t.Fatalf("insert old library: %v", err)
	}

	cfg := AttritionConfig{
		CycleStaleThreshold:   3,
		CycleRemovedThreshold: 7,
		NetworkStaleDays:      7,
		NetworkRemovedDays:    30,
		CycleBasedSources:    []string{"osquery"},
		NetworkBasedSources:  []string{"zeek_passive"},
	}

	summary, err := st.MarkStaleAssets(ctx, cfg)
	if err != nil {
		t.Fatalf("MarkStaleAssets: %v", err)
	}
	if summary.MarkedStale == 0 {
		t.Error("expected network-based asset to be marked stale")
	}
}

func TestReactivateAsset(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	host := seedHost(t, st)

	_, err := st.pool.Exec(ctx, `
		INSERT INTO ssh_keys (id, host_id, key_type, fingerprint_sha256, source, discovery_status)
		VALUES ('11111111-1111-1111-1111-111111111111', $1, 'ssh-ed25519', 'reactivate-fp', 'osquery', 'stale')
	`, host.ID)
	if err != nil {
		t.Fatalf("insert stale key: %v", err)
	}

	if err := st.ReactivateAsset(ctx, "ssh_key", "11111111-1111-1111-1111-111111111111"); err != nil {
		t.Fatalf("ReactivateAsset: %v", err)
	}

	got, err := st.GetSSHKey(ctx, "11111111-1111-1111-1111-111111111111")
	if err != nil {
		t.Fatalf("GetSSHKey: %v", err)
	}
	if got == nil {
		t.Fatal("expected SSH key after reactivation")
	}
	if got.DiscoveryStatus != "active" {
		t.Errorf("discovery_status = %q, want active", got.DiscoveryStatus)
	}
}

func TestMarkStaleAssets_NeverDeletes(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	host := seedHost(t, st)

	_, err := st.pool.Exec(ctx, `
		INSERT INTO ssh_keys (host_id, key_type, fingerprint_sha256, source, discovery_status, last_seen)
		VALUES ($1, 'ssh-ed25519', 'ancient-key', 'osquery', 'active', $2)
	`, host.ID, time.Now().Add(-365*24*time.Hour))
	if err != nil {
		t.Fatalf("insert ancient key: %v", err)
	}

	cfg := AttritionConfig{
		CycleStaleThreshold: 1, CycleRemovedThreshold: 2,
		NetworkStaleDays: 1, NetworkRemovedDays: 2,
		CycleBasedSources: []string{"osquery"},
		NetworkBasedSources: []string{"zeek_passive"},
	}

	if _, err := st.MarkStaleAssets(ctx, cfg); err != nil {
		t.Fatalf("MarkStaleAssets: %v", err)
	}

	result, err := st.ListSSHKeys(ctx, SSHKeySearchQuery{HostID: host.ID, Limit: 10})
	if err != nil {
		t.Fatalf("ListSSHKeys: %v", err)
	}
	if result.Total == 0 {
		t.Error("attrition should never delete rows, expected row to still exist")
	}
}
