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

package hostresolver

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

type mockStore struct {
	store.CryptoStore
	hosts       map[string]*model.Host
	identifiers map[string]string // "source:sourceHostID" -> hostID
	nextID      int
}

func newMockStore() *mockStore {
	return &mockStore{
		hosts:       map[string]*model.Host{},
		identifiers: map[string]string{},
	}
}

func (m *mockStore) FindHostBySourceID(ctx context.Context, source, sourceHostID string) (*model.Host, error) {
	key := source + ":" + sourceHostID
	if hostID, ok := m.identifiers[key]; ok {
		return m.hosts[hostID], nil
	}
	return nil, nil
}

func (m *mockStore) FindHostByIP(ctx context.Context, ip string) (*model.Host, error) {
	for _, h := range m.hosts {
		for _, hIP := range h.IPAddresses {
			if hIP == ip {
				return h, nil
			}
		}
	}
	return nil, nil
}

func (m *mockStore) FindHostByHostname(ctx context.Context, hostname string) (*model.Host, error) {
	for _, h := range m.hosts {
		if h.CanonicalHostname == hostname {
			return h, nil
		}
		for _, alias := range h.Aliases {
			if alias == hostname {
				return h, nil
			}
		}
	}
	return nil, nil
}

func (m *mockStore) UpsertHost(ctx context.Context, host *model.Host) error {
	if host.ID == "" {
		m.nextID++
		host.ID = fmt.Sprintf("host-%d", m.nextID)
		host.FirstSeen = time.Now()
		host.LastSeen = time.Now()
	}
	m.hosts[host.ID] = host
	return nil
}

func (m *mockStore) UpsertHostIdentifier(ctx context.Context, ident *model.HostIdentifier) error {
	key := ident.Source + ":" + ident.SourceHostID
	m.identifiers[key] = ident.HostID
	return nil
}

func TestResolveHost_CreateNew(t *testing.T) {
	st := newMockStore()
	r := NewResolver(st)
	ctx := context.Background()

	host, err := r.ResolveHost(ctx, "", "web-01.prod", []string{"10.0.1.5"}, "osquery", "linux")
	if err != nil {
		t.Fatalf("ResolveHost: %v", err)
	}
	if host == nil {
		t.Fatal("expected new host, got nil")
	}
	if host.CanonicalHostname != "web-01.prod" {
		t.Errorf("canonical_hostname = %q, want web-01.prod", host.CanonicalHostname)
	}
	if len(host.IPAddresses) != 1 || host.IPAddresses[0] != "10.0.1.5" {
		t.Errorf("ip_addresses = %v, want [10.0.1.5]", host.IPAddresses)
	}
}

func TestResolveHost_SourceIDMatch(t *testing.T) {
	st := newMockStore()
	existing := &model.Host{
		CanonicalHostname: "existing-host.prod",
		IPAddresses:       []string{"10.0.1.1"},
		Aliases:           []string{},
		DiscoverySources:  []string{"osquery"},
	}
	st.UpsertHost(context.Background(), existing)
	st.UpsertHostIdentifier(context.Background(), &model.HostIdentifier{
		HostID: existing.ID, Source: "osquery", SourceHostID: "osq-abc-123",
	})

	r := NewResolver(st)
	ctx := context.Background()

	host, err := r.ResolveHost(ctx, "osq-abc-123", "existing-host.prod", []string{"10.0.1.1", "10.0.1.2"}, "osquery", "")
	if err != nil {
		t.Fatalf("ResolveHost: %v", err)
	}
	if host.ID != existing.ID {
		t.Errorf("expected same host ID %q, got %q", existing.ID, host.ID)
	}
	// Should have merged the new IP
	hasNewIP := false
	for _, ip := range host.IPAddresses {
		if ip == "10.0.1.2" {
			hasNewIP = true
		}
	}
	if !hasNewIP {
		t.Errorf("expected merged IP 10.0.1.2, got %v", host.IPAddresses)
	}
}

func TestResolveHost_IPMatch(t *testing.T) {
	st := newMockStore()
	existing := &model.Host{
		CanonicalHostname: "ip-host.prod",
		IPAddresses:       []string{"10.0.2.5"},
		Aliases:           []string{},
		DiscoverySources:  []string{"zeek_passive"},
	}
	st.UpsertHost(context.Background(), existing)

	r := NewResolver(st)
	ctx := context.Background()

	host, err := r.ResolveHost(ctx, "", "different-hostname", []string{"10.0.2.5"}, "osquery", "")
	if err != nil {
		t.Fatalf("ResolveHost: %v", err)
	}
	if host.ID != existing.ID {
		t.Errorf("expected IP match to return existing host %q, got %q", existing.ID, host.ID)
	}
}

func TestResolveHost_HostnameMatch(t *testing.T) {
	st := newMockStore()
	existing := &model.Host{
		CanonicalHostname: "hostname-host.prod",
		IPAddresses:       []string{"10.0.3.1"},
		Aliases:           []string{"hostname-host"},
		DiscoverySources:  []string{"agent"},
	}
	st.UpsertHost(context.Background(), existing)

	r := NewResolver(st)
	ctx := context.Background()

	host, err := r.ResolveHost(ctx, "", "hostname-host", []string{"10.0.3.99"}, "osquery", "")
	if err != nil {
		t.Fatalf("ResolveHost: %v", err)
	}
	if host.ID != existing.ID {
		t.Errorf("expected hostname match to return existing host %q, got %q", existing.ID, host.ID)
	}
}

func TestResolveHost_MergesDiscoverySources(t *testing.T) {
	st := newMockStore()
	existing := &model.Host{
		CanonicalHostname: "merge-test.prod",
		IPAddresses:       []string{"10.0.4.1"},
		Aliases:           []string{},
		DiscoverySources:  []string{"zeek_passive"},
	}
	st.UpsertHost(context.Background(), existing)

	r := NewResolver(st)
	ctx := context.Background()

	host, err := r.ResolveHost(ctx, "", "merge-test.prod", []string{"10.0.4.1"}, "osquery", "")
	if err != nil {
		t.Fatalf("ResolveHost: %v", err)
	}

	hasBothSources := false
	hasZeek := false
	hasOsquery := false
	for _, s := range host.DiscoverySources {
		if s == "zeek_passive" {
			hasZeek = true
		}
		if s == "osquery" {
			hasOsquery = true
		}
	}
	hasBothSources = hasZeek && hasOsquery
	if !hasBothSources {
		t.Errorf("expected both sources, got %v", host.DiscoverySources)
	}
}

func TestResolveHost_RegistersSourceHostID(t *testing.T) {
	st := newMockStore()
	r := NewResolver(st)
	ctx := context.Background()

	host, err := r.ResolveHost(ctx, "new-source-id", "new-host.prod", []string{"10.0.5.1"}, "osquery", "")
	if err != nil {
		t.Fatalf("ResolveHost: %v", err)
	}

	// Verify the identifier was registered
	found, err := st.FindHostBySourceID(ctx, "osquery", "new-source-id")
	if err != nil {
		t.Fatalf("FindHostBySourceID: %v", err)
	}
	if found == nil || found.ID != host.ID {
		t.Error("expected source host ID to be registered")
	}
}
