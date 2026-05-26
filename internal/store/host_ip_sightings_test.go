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
	"strings"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

// Shared time origin for these tests — one arbitrary instant so the
// BETWEEN arithmetic in GetHostIPSightingsForIP is deterministic.
var hipTestNow = time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC)

// seedHostForSighting returns a persisted host the sighting tests can
// attribute rows to. Identical to provenance_test.go's helper shape but
// local to avoid coupling.
func seedHostForSighting(t *testing.T, st *PostgresStore) *model.Host {
	t.Helper()
	h := &model.Host{
		CanonicalHostname: "sighting-test.example.com",
		IPAddresses:       []string{"10.99.0.1"},
		DiscoverySources:  []string{"test"},
	}
	if err := st.UpsertHost(context.Background(), h); err != nil {
		t.Fatalf("seed host: %v", err)
	}
	return h
}

func TestUpsertHostIPSighting_InsertAndRoundTrip(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	host := seedHostForSighting(t, st)

	s := &HostIPSighting{
		HostID:     host.ID,
		IP:         "10.20.4.10",
		FirstSeen:  hipTestNow,
		LastSeen:   hipTestNow.Add(8 * time.Hour),
		Source:     "dhcp",
		Confidence: "attested",
		Attribution: map[string]any{
			"mac":            "aa:bb:cc:dd:ee:01",
			"host_name":      "laptop-01",
			"client_fqdn":    "laptop-01.corp.example.com",
			"lease_time_sec": 604800,
		},
	}
	if err := st.UpsertHostIPSighting(ctx, s); err != nil {
		t.Fatalf("UpsertHostIPSighting: %v", err)
	}
	if s.ID == "" {
		t.Fatal("expected ID populated after insert")
	}

	got, err := st.GetHostIPSightingsForIP(ctx, "10.20.4.10", hipTestNow.Add(1*time.Hour))
	if err != nil {
		t.Fatalf("GetHostIPSightingsForIP: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("row count = %d, want 1", len(got))
	}
	if got[0].Source != "dhcp" || got[0].Confidence != "attested" {
		t.Errorf("source/confidence = %q/%q, want dhcp/attested", got[0].Source, got[0].Confidence)
	}
	if got[0].Attribution["mac"] != "aa:bb:cc:dd:ee:01" {
		t.Errorf("attribution.mac = %v, want aa:bb:cc:dd:ee:01", got[0].Attribution["mac"])
	}
}

// TestUpsertHostIPSighting_DedupesNullHost exercises the v1.5.0 design
// guarantee that two observations of the same (source, ip) with
// host_id=NULL merge into a single row — the idx_hip_unique functional
// index using COALESCE(host_id, zero-UUID) covers this. Spec §10 Upsert
// semantics.
func TestUpsertHostIPSighting_DedupesNullHost(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	first := &HostIPSighting{
		IP:         "10.0.0.42",
		FirstSeen:  hipTestNow,
		LastSeen:   hipTestNow.Add(24 * time.Hour),
		Source:     "zeek_known_hosts",
		Confidence: "observed",
	}
	if err := st.UpsertHostIPSighting(ctx, first); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	firstID := first.ID

	// Later observation on the same IP, same source, still unattributed.
	// Should merge into the existing row, not create a new one.
	second := &HostIPSighting{
		IP:         "10.0.0.42",
		FirstSeen:  hipTestNow.Add(12 * time.Hour),
		LastSeen:   hipTestNow.Add(36 * time.Hour),
		Source:     "zeek_known_hosts",
		Confidence: "observed",
	}
	if err := st.UpsertHostIPSighting(ctx, second); err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	if second.ID != firstID {
		t.Errorf("expected same ID after merge, got %q → %q", firstID, second.ID)
	}

	total, err := st.CountHostIPSightings(ctx, "zeek_known_hosts")
	if err != nil {
		t.Fatalf("CountHostIPSightings: %v", err)
	}
	if total != 1 {
		t.Errorf("row count = %d, want 1 (should have merged)", total)
	}

	// Window should be expanded to [first.FirstSeen, second.LastSeen] —
	// never shrunk by a stale observation.
	var gotFirst, gotLast time.Time
	if err := st.pool.QueryRow(ctx,
		`SELECT first_seen, last_seen FROM host_ip_sightings WHERE id = $1`, firstID,
	).Scan(&gotFirst, &gotLast); err != nil {
		t.Fatalf("read merged row: %v", err)
	}
	if !gotFirst.Equal(hipTestNow) {
		t.Errorf("first_seen = %v, want %v (must not be shrunk)", gotFirst, hipTestNow)
	}
	if !gotLast.Equal(hipTestNow.Add(36 * time.Hour)) {
		t.Errorf("last_seen = %v, want %v (must be extended)", gotLast, hipTestNow.Add(36*time.Hour))
	}
}

// TestUpsertHostIPSighting_DistinctHostsCoexist covers the conflict case:
// two sightings for the SAME ip + source but DIFFERENT host_ids must
// land as separate rows. The blast-radius conflict-flag query surfaces
// this configuration (spec §3.3).
func TestUpsertHostIPSighting_DistinctHostsCoexist(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	hostA := &model.Host{CanonicalHostname: "A", IPAddresses: []string{"10.5.0.1"}, DiscoverySources: []string{"test"}}
	hostB := &model.Host{CanonicalHostname: "B", IPAddresses: []string{"10.5.0.2"}, DiscoverySources: []string{"test"}}
	if err := st.UpsertHost(ctx, hostA); err != nil {
		t.Fatalf("seed hostA: %v", err)
	}
	if err := st.UpsertHost(ctx, hostB); err != nil {
		t.Fatalf("seed hostB: %v", err)
	}

	sightA := &HostIPSighting{
		HostID: hostA.ID, IP: "10.5.0.99",
		FirstSeen: hipTestNow, LastSeen: hipTestNow.Add(2 * time.Hour),
		Source: "dhcp", Confidence: "attested",
	}
	sightB := &HostIPSighting{
		HostID: hostB.ID, IP: "10.5.0.99",
		FirstSeen: hipTestNow.Add(1 * time.Hour), LastSeen: hipTestNow.Add(3 * time.Hour),
		Source: "dhcp", Confidence: "attested",
	}
	if err := st.UpsertHostIPSighting(ctx, sightA); err != nil {
		t.Fatalf("upsert A: %v", err)
	}
	if err := st.UpsertHostIPSighting(ctx, sightB); err != nil {
		t.Fatalf("upsert B: %v", err)
	}

	total, err := st.CountHostIPSightings(ctx, "dhcp")
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if total != 2 {
		t.Errorf("row count = %d, want 2 (different hosts must not merge)", total)
	}

	// Query at the overlapping moment — both rows active at t+1.5h.
	got, err := st.GetHostIPSightingsForIP(ctx, "10.5.0.99", hipTestNow.Add(90*time.Minute))
	if err != nil {
		t.Fatalf("query overlap: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("overlap query returned %d rows, want 2", len(got))
	}
}

// TestGetHostIPSightingsForIP_PointInTime confirms the BETWEEN semantics
// of the point-in-time lookup. A sighting valid [T, T+1h] must be
// returned for any observation timestamp in that closed interval and
// filtered out before/after.
func TestGetHostIPSightingsForIP_PointInTime(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	host := seedHostForSighting(t, st)

	windowStart := hipTestNow
	windowEnd := hipTestNow.Add(1 * time.Hour)

	s := &HostIPSighting{
		HostID:     host.ID,
		IP:         "10.20.4.10",
		FirstSeen:  windowStart,
		LastSeen:   windowEnd,
		Source:     "endpoint",
		Confidence: "direct",
	}
	if err := st.UpsertHostIPSighting(ctx, s); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	cases := []struct {
		name string
		at   time.Time
		want int
	}{
		{"inside window", windowStart.Add(15 * time.Minute), 1},
		{"on lower boundary (inclusive)", windowStart, 1},
		{"on upper boundary (inclusive)", windowEnd, 1},
		{"just before", windowStart.Add(-1 * time.Second), 0},
		{"just after", windowEnd.Add(1 * time.Second), 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := st.GetHostIPSightingsForIP(ctx, "10.20.4.10", c.at)
			if err != nil {
				t.Fatalf("query: %v", err)
			}
			if len(got) != c.want {
				t.Errorf("got %d rows, want %d", len(got), c.want)
			}
		})
	}
}

// TestGetHostIPSightingsForIP_ExcludesNullHost confirms that only
// attributed sightings are returned. Unattributed rows (host_id NULL)
// are the responsibility of the separate unattributed-aggregate query
// path (spec §3.3) — this method MUST NOT include them.
func TestGetHostIPSightingsForIP_ExcludesNullHost(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	s := &HostIPSighting{
		IP: "10.0.0.9", FirstSeen: hipTestNow, LastSeen: hipTestNow.Add(1 * time.Hour),
		Source: "zeek_known_hosts", Confidence: "observed",
	}
	if err := st.UpsertHostIPSighting(ctx, s); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	got, err := st.GetHostIPSightingsForIP(ctx, "10.0.0.9", hipTestNow.Add(30*time.Minute))
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d rows, want 0 (unattributed rows must not surface here)", len(got))
	}
}

// TestGetHostIPSightingsForIP_TierOrdering covers the strongest-tier-
// first ordering that the blast-radius CTE depends on. direct wins,
// then attested, then inferred, then observed.
func TestGetHostIPSightingsForIP_TierOrdering(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	hostA := &model.Host{CanonicalHostname: "A", IPAddresses: []string{"10.10.0.1"}, DiscoverySources: []string{"test"}}
	hostB := &model.Host{CanonicalHostname: "B", IPAddresses: []string{"10.10.0.2"}, DiscoverySources: []string{"test"}}
	hostC := &model.Host{CanonicalHostname: "C", IPAddresses: []string{"10.10.0.3"}, DiscoverySources: []string{"test"}}
	for _, h := range []*model.Host{hostA, hostB, hostC} {
		if err := st.UpsertHost(ctx, h); err != nil {
			t.Fatalf("seed host: %v", err)
		}
	}

	// All three sightings share the same IP + window; different hosts,
	// different confidence tiers — the ordering must surface them in
	// tier order.
	sights := []*HostIPSighting{
		{HostID: hostA.ID, IP: "10.10.0.99",
			FirstSeen: hipTestNow, LastSeen: hipTestNow.Add(1 * time.Hour),
			Source: "zeek_known_hosts", Confidence: "observed"},
		{HostID: hostB.ID, IP: "10.10.0.99",
			FirstSeen: hipTestNow, LastSeen: hipTestNow.Add(1 * time.Hour),
			Source: "endpoint", Confidence: "direct"},
		{HostID: hostC.ID, IP: "10.10.0.99",
			FirstSeen: hipTestNow, LastSeen: hipTestNow.Add(1 * time.Hour),
			Source: "dhcp", Confidence: "attested"},
	}
	for _, s := range sights {
		if err := st.UpsertHostIPSighting(ctx, s); err != nil {
			t.Fatalf("upsert %s/%s: %v", s.Source, s.Confidence, err)
		}
	}

	got, err := st.GetHostIPSightingsForIP(ctx, "10.10.0.99", hipTestNow.Add(30*time.Minute))
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("rows = %d, want 3", len(got))
	}
	wantOrder := []string{"direct", "attested", "observed"}
	for i, want := range wantOrder {
		if got[i].Confidence != want {
			t.Errorf("row[%d].confidence = %q, want %q (tier ordering broken)", i, got[i].Confidence, want)
		}
	}
}

func TestPruneHostIPSightings(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	host := seedHostForSighting(t, st)

	old := &HostIPSighting{
		HostID: host.ID, IP: "10.20.4.10",
		FirstSeen: hipTestNow.Add(-10 * 24 * time.Hour),
		LastSeen:  hipTestNow.Add(-8 * 24 * time.Hour), // 8 days old
		Source:    "dhcp", Confidence: "attested",
	}
	fresh := &HostIPSighting{
		HostID: host.ID, IP: "10.20.4.11",
		FirstSeen: hipTestNow.Add(-1 * 24 * time.Hour),
		LastSeen:  hipTestNow,
		Source:    "dhcp", Confidence: "attested",
	}
	onBoundary := &HostIPSighting{
		HostID: host.ID, IP: "10.20.4.12",
		FirstSeen: hipTestNow.Add(-9 * 24 * time.Hour),
		LastSeen:  hipTestNow.Add(-7 * 24 * time.Hour), // exactly on cutoff
		Source:    "dhcp", Confidence: "attested",
	}
	for _, s := range []*HostIPSighting{old, fresh, onBoundary} {
		if err := st.UpsertHostIPSighting(ctx, s); err != nil {
			t.Fatalf("seed %s: %v", s.IP, err)
		}
	}

	cutoff := hipTestNow.Add(-7 * 24 * time.Hour) // 7-day retention
	deleted, err := st.PruneHostIPSightings(ctx, cutoff)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	// Only `old` is strictly before cutoff. `onBoundary.last_seen = cutoff`
	// must survive under the `< cutoff` semantics.
	if deleted != 1 {
		t.Errorf("deleted = %d, want 1 (strictly-before semantics)", deleted)
	}
	remaining, err := st.CountHostIPSightings(ctx, "")
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if remaining != 2 {
		t.Errorf("remaining = %d, want 2", remaining)
	}
}

// TestHostIPSightings_CheckConstraints regresses against migration 024's
// CHECK clauses. Malformed rows must be rejected at the DB layer even
// if a buggy ingester produces them.
func TestHostIPSightings_CheckConstraints(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	host := seedHostForSighting(t, st)

	cases := []struct {
		name       string
		source     string
		confidence string
		first      time.Time
		last       time.Time
		wantErrSub string
	}{
		{
			name: "bad source", source: "unknown_source", confidence: "direct",
			first: hipTestNow, last: hipTestNow.Add(1 * time.Hour),
			wantErrSub: "host_ip_sightings_source_check",
		},
		{
			name: "bad confidence", source: "endpoint", confidence: "super_certain",
			first: hipTestNow, last: hipTestNow.Add(1 * time.Hour),
			wantErrSub: "host_ip_sightings_confidence_check",
		},
		{
			name: "inverted window", source: "endpoint", confidence: "direct",
			first: hipTestNow.Add(1 * time.Hour), last: hipTestNow,
			wantErrSub: "host_ip_sightings_window_check",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := &HostIPSighting{
				HostID: host.ID, IP: "10.20.4.10",
				FirstSeen: c.first, LastSeen: c.last,
				Source: c.source, Confidence: c.confidence,
			}
			err := st.UpsertHostIPSighting(ctx, s)
			if err == nil {
				t.Fatal("expected CHECK constraint violation, got nil")
			}
			if !strings.Contains(err.Error(), c.wantErrSub) {
				t.Errorf("err = %v, want containing %q", err, c.wantErrSub)
			}
		})
	}
}
