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

func TestUpsertAndGetHost(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	host := &model.Host{
		CanonicalHostname: "web-01.prod.example.com",
		Aliases:           []string{"web-01"},
		IPAddresses:       []string{"10.0.1.5"},
		OSFamily:          "linux",
		OSVersion:         "Ubuntu 22.04",
		HostType:          "server",
		DiscoverySources:  []string{"osquery"},
		FirstSeen:         time.Now().Truncate(time.Microsecond),
		LastSeen:          time.Now().Truncate(time.Microsecond),
	}

	if err := st.UpsertHost(ctx, host); err != nil {
		t.Fatalf("UpsertHost: %v", err)
	}
	if host.ID == "" {
		t.Fatal("expected host ID to be populated after upsert")
	}

	got, err := st.GetHost(ctx, host.ID)
	if err != nil {
		t.Fatalf("GetHost: %v", err)
	}
	if got == nil {
		t.Fatal("expected host, got nil")
	}
	if got.CanonicalHostname != "web-01.prod.example.com" {
		t.Errorf("canonical_hostname = %q, want web-01.prod.example.com", got.CanonicalHostname)
	}
	if got.OSFamily != "linux" {
		t.Errorf("os_family = %q, want linux", got.OSFamily)
	}
	if len(got.IPAddresses) != 1 || got.IPAddresses[0] != "10.0.1.5" {
		t.Errorf("ip_addresses = %v, want [10.0.1.5]", got.IPAddresses)
	}
}

func TestGetHost_NotFound(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	got, err := st.GetHost(ctx, "00000000-0000-0000-0000-000000000000")
	if err != nil {
		t.Fatalf("GetHost: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil for missing host, got %+v", got)
	}
}

func TestFindHostByIP(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	host := &model.Host{
		CanonicalHostname: "db-01.prod",
		IPAddresses:       []string{"10.0.2.10", "10.0.2.11"},
		DiscoverySources:  []string{"zeek_passive"},
	}
	if err := st.UpsertHost(ctx, host); err != nil {
		t.Fatalf("UpsertHost: %v", err)
	}

	got, err := st.FindHostByIP(ctx, "10.0.2.11")
	if err != nil {
		t.Fatalf("FindHostByIP: %v", err)
	}
	if got == nil {
		t.Fatal("expected host, got nil")
	}
	if got.ID != host.ID {
		t.Errorf("found host ID = %q, want %q", got.ID, host.ID)
	}
}

func TestFindHostByIP_NotFound(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	got, err := st.FindHostByIP(ctx, "192.168.99.99")
	if err != nil {
		t.Fatalf("FindHostByIP: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil, got %+v", got)
	}
}

func TestFindHostByHostname(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	host := &model.Host{
		CanonicalHostname: "app-01.staging",
		Aliases:           []string{"app-01"},
		IPAddresses:       []string{"10.0.3.1"},
		DiscoverySources:  []string{"agent"},
	}
	if err := st.UpsertHost(ctx, host); err != nil {
		t.Fatalf("UpsertHost: %v", err)
	}

	// Find by canonical hostname
	got, err := st.FindHostByHostname(ctx, "app-01.staging")
	if err != nil {
		t.Fatalf("FindHostByHostname canonical: %v", err)
	}
	if got == nil || got.ID != host.ID {
		t.Error("expected to find host by canonical hostname")
	}

	// Find by alias
	got2, err := st.FindHostByHostname(ctx, "app-01")
	if err != nil {
		t.Fatalf("FindHostByHostname alias: %v", err)
	}
	if got2 == nil || got2.ID != host.ID {
		t.Error("expected to find host by alias")
	}
}

func TestListHosts(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	for i, name := range []string{"host-a.prod", "host-b.prod", "host-c.staging"} {
		h := &model.Host{
			CanonicalHostname: name,
			IPAddresses:       []string{"10.0.0." + string(rune('1'+i))},
			HostType:          "server",
			DiscoverySources:  []string{"osquery"},
		}
		if err := st.UpsertHost(ctx, h); err != nil {
			t.Fatalf("UpsertHost %s: %v", name, err)
		}
	}

	result, err := st.ListHosts(ctx, HostSearchQuery{Limit: 10})
	if err != nil {
		t.Fatalf("ListHosts: %v", err)
	}
	if result.Total != 3 {
		t.Errorf("total = %d, want 3", result.Total)
	}
	if len(result.Hosts) != 3 {
		t.Errorf("hosts count = %d, want 3", len(result.Hosts))
	}

	// Test pagination
	result2, err := st.ListHosts(ctx, HostSearchQuery{Limit: 2, Offset: 0})
	if err != nil {
		t.Fatalf("ListHosts paginated: %v", err)
	}
	if len(result2.Hosts) != 2 {
		t.Errorf("paginated hosts count = %d, want 2", len(result2.Hosts))
	}
	if result2.Total != 3 {
		t.Errorf("paginated total = %d, want 3", result2.Total)
	}
}

func TestMergeHosts(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	target := &model.Host{
		CanonicalHostname: "target-host.prod",
		IPAddresses:       []string{"10.0.1.1"},
		Aliases:           []string{"target"},
		DiscoverySources:  []string{"osquery"},
	}
	source := &model.Host{
		CanonicalHostname: "source-host.prod",
		IPAddresses:       []string{"10.0.1.2"},
		Aliases:           []string{"source"},
		DiscoverySources:  []string{"agent"},
	}
	if err := st.UpsertHost(ctx, target); err != nil {
		t.Fatalf("UpsertHost target: %v", err)
	}
	if err := st.UpsertHost(ctx, source); err != nil {
		t.Fatalf("UpsertHost source: %v", err)
	}

	// Add an SSH key to source host to verify FK migration
	key := &model.SSHKey{
		HostID:            source.ID,
		KeyType:           "ssh-ed25519",
		FingerprintSHA256: "abc123",
		Source:            "agent",
		DiscoveryStatus:   "active",
	}
	if err := st.UpsertSSHKey(ctx, key); err != nil {
		t.Fatalf("UpsertSSHKey: %v", err)
	}

	if err := st.MergeHosts(ctx, target.ID, source.ID); err != nil {
		t.Fatalf("MergeHosts: %v", err)
	}

	// Source host should be deleted
	gone, err := st.GetHost(ctx, source.ID)
	if err != nil {
		t.Fatalf("GetHost source after merge: %v", err)
	}
	if gone != nil {
		t.Error("expected source host to be deleted after merge")
	}

	// Target should have merged IPs
	merged, err := st.GetHost(ctx, target.ID)
	if err != nil {
		t.Fatalf("GetHost target after merge: %v", err)
	}
	if merged == nil {
		t.Fatal("expected target host to exist after merge")
	}

	hasIP := false
	for _, ip := range merged.IPAddresses {
		if ip == "10.0.1.2" {
			hasIP = true
		}
	}
	if !hasIP {
		t.Errorf("merged host IPs = %v, expected to contain 10.0.1.2", merged.IPAddresses)
	}
}

func TestUpsertHostIdentifier_And_FindBySourceID(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	host := &model.Host{
		CanonicalHostname: "identified-host.prod",
		IPAddresses:       []string{"10.0.5.1"},
		DiscoverySources:  []string{"osquery"},
	}
	if err := st.UpsertHost(ctx, host); err != nil {
		t.Fatalf("UpsertHost: %v", err)
	}

	ident := &model.HostIdentifier{
		HostID:       host.ID,
		Source:       "osquery",
		SourceHostID: "osquery-host-abc-123",
	}
	if err := st.UpsertHostIdentifier(ctx, ident); err != nil {
		t.Fatalf("UpsertHostIdentifier: %v", err)
	}

	got, err := st.FindHostBySourceID(ctx, "osquery", "osquery-host-abc-123")
	if err != nil {
		t.Fatalf("FindHostBySourceID: %v", err)
	}
	if got == nil {
		t.Fatal("expected host, got nil")
	}
	if got.ID != host.ID {
		t.Errorf("found host ID = %q, want %q", got.ID, host.ID)
	}

	// Not found case
	missing, err := st.FindHostBySourceID(ctx, "osquery", "nonexistent")
	if err != nil {
		t.Fatalf("FindHostBySourceID not found: %v", err)
	}
	if missing != nil {
		t.Errorf("expected nil, got %+v", missing)
	}
}
