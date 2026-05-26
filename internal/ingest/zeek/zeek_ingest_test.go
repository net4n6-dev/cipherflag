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

package zeek

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// ── known_hosts parser + mapper ───────────────────────────────────────

func TestParseKnownHostsRecord_Canonical(t *testing.T) {
	line := []byte(`{"ts":1776000000.5,"host":"10.20.4.10"}`)
	rec, err := ParseKnownHostsRecord(line)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if rec.Host != "10.20.4.10" {
		t.Errorf("host = %q, want 10.20.4.10", rec.Host)
	}
	if rec.Timestamp.Unix() != 1776000000 {
		t.Errorf("timestamp = %v, want unix 1776000000", rec.Timestamp)
	}
}

func TestMapKnownHostsToSighting_Shape(t *testing.T) {
	ts := time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC)
	rec := &KnownHostsRecord{Timestamp: ts, Host: "10.20.4.10"}
	s := MapKnownHostsToSighting(rec)

	if s.Source != "zeek_known_hosts" {
		t.Errorf("source = %q, want zeek_known_hosts", s.Source)
	}
	if s.Confidence != "observed" {
		t.Errorf("confidence = %q, want observed", s.Confidence)
	}
	if s.HostID != "" {
		t.Errorf("host_id = %q, want empty (unattributed)", s.HostID)
	}
	if !s.FirstSeen.Equal(ts) {
		t.Errorf("first_seen = %v, want %v", s.FirstSeen, ts)
	}
	if !s.LastSeen.Equal(ts.Add(24 * time.Hour)) {
		t.Errorf("last_seen = %v, want ts+24h", s.LastSeen)
	}
}

// ── dhcp parser ───────────────────────────────────────────────────────

func TestParseDHCPRecord_FullAggregatedTransaction(t *testing.T) {
	line := []byte(`{
		"ts": 1776000000,
		"mac": "aa:bb:cc:dd:ee:01",
		"host_name": "laptop-01",
		"client_fqdn": "laptop-01.corp.example.com",
		"domain": "corp.example.com",
		"assigned_addr": "10.20.4.50",
		"requested_addr": "10.20.4.50",
		"lease_time": 604800,
		"msg_types": ["DISCOVER","OFFER","REQUEST","ACK"],
		"client_addr": "10.20.4.50",
		"server_addr": "10.20.0.1"
	}`)
	rec, err := ParseDHCPRecord(line)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if rec.MAC != "aa:bb:cc:dd:ee:01" || rec.AssignedAddr != "10.20.4.50" {
		t.Errorf("mac/ip = %q/%q", rec.MAC, rec.AssignedAddr)
	}
	if rec.HostName != "laptop-01" || rec.ClientFQDN != "laptop-01.corp.example.com" {
		t.Errorf("names = %q / %q", rec.HostName, rec.ClientFQDN)
	}
	if rec.LeaseTime != 7*24*time.Hour {
		t.Errorf("lease_time = %v, want 7d", rec.LeaseTime)
	}
	if len(rec.MsgTypes) != 4 || rec.MsgTypes[3] != "ACK" {
		t.Errorf("msg_types = %v", rec.MsgTypes)
	}
}

func TestParseDHCPRecord_OptionalsAbsent(t *testing.T) {
	// Minimal DHCP record: some clients don't send host_name / fqdn /
	// requested_addr. The parser must tolerate nullable fields.
	line := []byte(`{
		"ts": 1776000000,
		"mac": "aa:bb:cc:dd:ee:02",
		"assigned_addr": "10.20.4.51",
		"msg_types": ["REQUEST","ACK"]
	}`)
	rec, err := ParseDHCPRecord(line)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if rec.HostName != "" || rec.ClientFQDN != "" || rec.RequestedAddr != "" {
		t.Errorf("absent fields should be empty strings; got %+v", rec)
	}
	if rec.LeaseTime != 0 {
		t.Errorf("lease_time = %v, want zero when absent", rec.LeaseTime)
	}
}

// ── dhcp mapper ───────────────────────────────────────────────────────

// fakeDHCPStore records every call so tests can assert the orchestration
// between FindHostBySourceID → UpsertHost → UpsertHostIdentifier →
// UpsertHostIPSighting.
type fakeDHCPStore struct {
	// Lookup table indexed by (source, source_host_id).
	hosts map[string]*model.Host
	// Last recorded calls.
	upsertHostCalls       []*model.Host
	upsertIdentifierCalls []*model.HostIdentifier
	upsertSightingCalls   []*store.HostIPSighting

	findErr error
}

func newFakeDHCPStore() *fakeDHCPStore {
	return &fakeDHCPStore{hosts: map[string]*model.Host{}}
}

func (f *fakeDHCPStore) key(source, id string) string { return source + "|" + id }

func (f *fakeDHCPStore) FindHostBySourceID(_ context.Context, source, id string) (*model.Host, error) {
	if f.findErr != nil {
		return nil, f.findErr
	}
	return f.hosts[f.key(source, id)], nil
}

func (f *fakeDHCPStore) UpsertHost(_ context.Context, h *model.Host) error {
	if h.ID == "" {
		h.ID = "host-" + h.CanonicalHostname
		if h.CanonicalHostname == "" {
			h.ID = "host-anon-" + string(rune('A'+len(f.upsertHostCalls)))
		}
	}
	f.upsertHostCalls = append(f.upsertHostCalls, h)
	return nil
}

func (f *fakeDHCPStore) UpsertHostIdentifier(_ context.Context, ident *model.HostIdentifier) error {
	f.upsertIdentifierCalls = append(f.upsertIdentifierCalls, ident)
	// Mirror the identifier into the lookup map so a subsequent
	// FindHostBySourceID resolves.
	for _, h := range f.upsertHostCalls {
		if h.ID == ident.HostID {
			f.hosts[f.key(ident.Source, ident.SourceHostID)] = h
			return nil
		}
	}
	return nil
}

func (f *fakeDHCPStore) UpsertHostIPSighting(_ context.Context, s *store.HostIPSighting) error {
	f.upsertSightingCalls = append(f.upsertSightingCalls, s)
	return nil
}

func TestIngestDHCPRecord_AutoCreatesHost(t *testing.T) {
	f := newFakeDHCPStore()
	ctx := context.Background()

	ts := time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC)
	rec := &DHCPRecord{
		Timestamp: ts, MAC: "aa:bb:cc:dd:ee:03",
		HostName: "newhost", ClientFQDN: "newhost.corp.example.com",
		AssignedAddr: "10.20.4.60", LeaseTime: 8 * time.Hour,
		MsgTypes: []string{"REQUEST", "ACK"},
	}
	if err := IngestDHCPRecord(ctx, f, rec); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	if len(f.upsertHostCalls) != 1 {
		t.Fatalf("upsertHost calls = %d, want 1", len(f.upsertHostCalls))
	}
	h := f.upsertHostCalls[0]
	if h.CanonicalHostname != "newhost.corp.example.com" {
		t.Errorf("canonical = %q, want FQDN preferred over short host_name", h.CanonicalHostname)
	}
	if len(h.IPAddresses) != 1 || h.IPAddresses[0] != "10.20.4.60" {
		t.Errorf("ip_addresses = %v, want [10.20.4.60]", h.IPAddresses)
	}

	if len(f.upsertIdentifierCalls) != 1 {
		t.Fatalf("identifier calls = %d, want 1", len(f.upsertIdentifierCalls))
	}
	ident := f.upsertIdentifierCalls[0]
	if ident.Source != "dhcp_mac" || ident.SourceHostID != "aa:bb:cc:dd:ee:03" {
		t.Errorf("identifier = %+v, want dhcp_mac/aa:bb:cc:dd:ee:03", ident)
	}

	if len(f.upsertSightingCalls) != 1 {
		t.Fatalf("sighting calls = %d, want 1", len(f.upsertSightingCalls))
	}
	s := f.upsertSightingCalls[0]
	if s.Source != "dhcp" || s.Confidence != "attested" {
		t.Errorf("sighting tier = %s/%s, want dhcp/attested", s.Source, s.Confidence)
	}
	if !s.FirstSeen.Equal(ts) || !s.LastSeen.Equal(ts.Add(8*time.Hour)) {
		t.Errorf("window = [%v..%v], want ts..ts+8h", s.FirstSeen, s.LastSeen)
	}
	if s.Attribution["mac"] != "aa:bb:cc:dd:ee:03" {
		t.Errorf("attribution.mac = %v", s.Attribution["mac"])
	}
	if leaseSec, _ := s.Attribution["lease_time_sec"].(int); leaseSec != 8*3600 {
		t.Errorf("lease_time_sec = %v, want %d", s.Attribution["lease_time_sec"], 8*3600)
	}
}

func TestIngestDHCPRecord_ReusesExistingHost(t *testing.T) {
	f := newFakeDHCPStore()
	ctx := context.Background()

	// Pre-seed: an existing host already has a dhcp_mac identifier.
	existing := &model.Host{ID: "existing-host-1", CanonicalHostname: "known.corp"}
	f.hosts[f.key("dhcp_mac", "aa:bb:cc:dd:ee:04")] = existing

	rec := &DHCPRecord{
		Timestamp: time.Now(), MAC: "aa:bb:cc:dd:ee:04",
		AssignedAddr: "10.20.4.70", LeaseTime: 1 * time.Hour,
		MsgTypes: []string{"REQUEST", "ACK"},
	}
	if err := IngestDHCPRecord(ctx, f, rec); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	if len(f.upsertHostCalls) != 0 {
		t.Errorf("upsertHost called %d times on known MAC; want 0", len(f.upsertHostCalls))
	}
	if len(f.upsertIdentifierCalls) != 0 {
		t.Errorf("identifier created %d times on known MAC; want 0", len(f.upsertIdentifierCalls))
	}
	if len(f.upsertSightingCalls) != 1 {
		t.Fatalf("sighting calls = %d, want 1", len(f.upsertSightingCalls))
	}
	if f.upsertSightingCalls[0].HostID != "existing-host-1" {
		t.Errorf("sighting host_id = %q, want existing-host-1", f.upsertSightingCalls[0].HostID)
	}
}

func TestIngestDHCPRecord_SkipsMissingMAC(t *testing.T) {
	f := newFakeDHCPStore()
	rec := &DHCPRecord{Timestamp: time.Now(), AssignedAddr: "10.0.0.1"}
	if err := IngestDHCPRecord(context.Background(), f, rec); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(f.upsertHostCalls)+len(f.upsertSightingCalls) != 0 {
		t.Errorf("store touched on MAC-less record; want no-op")
	}
}

func TestIngestDHCPRecord_SkipsMissingIP(t *testing.T) {
	f := newFakeDHCPStore()
	rec := &DHCPRecord{Timestamp: time.Now(), MAC: "aa:bb:cc:dd:ee:ff"}
	if err := IngestDHCPRecord(context.Background(), f, rec); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(f.upsertHostCalls)+len(f.upsertSightingCalls) != 0 {
		t.Errorf("store touched on IP-less record; want no-op")
	}
}

func TestIngestDHCPRecord_DefaultLeaseFallback(t *testing.T) {
	f := newFakeDHCPStore()
	ctx := context.Background()
	ts := time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC)
	rec := &DHCPRecord{
		Timestamp: ts, MAC: "aa:bb:cc:dd:ee:05",
		AssignedAddr: "10.20.4.80",
		// LeaseTime deliberately zero — client didn't send option 51.
	}
	if err := IngestDHCPRecord(ctx, f, rec); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	s := f.upsertSightingCalls[0]
	if !s.LastSeen.Equal(ts.Add(DefaultLeaseFallback)) {
		t.Errorf("window without lease_time extends to %v, want ts + %v", s.LastSeen, DefaultLeaseFallback)
	}
}

func TestIngestDHCPRecord_LookupErrorPropagates(t *testing.T) {
	f := newFakeDHCPStore()
	f.findErr = errors.New("pg connection died")
	rec := &DHCPRecord{
		Timestamp: time.Now(), MAC: "aa:bb:cc:dd:ee:06", AssignedAddr: "10.20.4.90",
	}
	err := IngestDHCPRecord(context.Background(), f, rec)
	if err == nil {
		t.Fatal("expected lookup error to propagate")
	}
}
