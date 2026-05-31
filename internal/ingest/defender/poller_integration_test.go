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
//go:build integration

package defender

import (
	"context"
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/ingest"
	"github.com/net4n6-dev/cipherflag/internal/store"
	"github.com/net4n6-dev/cipherflag/internal/testdb"
)

func newTestStore(t *testing.T) *store.PostgresStore {
	t.Helper()
	dsn := testdb.Require(t)
	st, err := store.NewPostgresStore(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// Clean slate for the tables this test touches.
	_, _ = st.Pool().Exec(context.Background(), "TRUNCATE crypto_libraries, host_identifiers, hosts, asset_provenance, ingestion_state RESTART IDENTITY CASCADE")
	return st
}

func TestPollerIntegration_EndToEnd(t *testing.T) {
	st := newTestStore(t)
	ing := ingest.NewUnifiedIngester(st)

	mock := NewMockClient()
	mock.Rows = loadResponseRows(t, "advanced_hunting_response.json")

	cfg := config.DefenderSourceConfig{Enabled: true, PollIntervalSeconds: 60}
	p := newPoller(mock, ing, st, cfg)

	if err := p.runCycle(context.Background()); err != nil {
		t.Fatalf("runCycle: %v", err)
	}

	// Verify host for device-001 was created.
	host, err := st.FindHostBySourceID(context.Background(), "defender", "device-001")
	if err != nil {
		t.Fatalf("FindHostBySourceID: %v", err)
	}
	if host == nil {
		t.Fatal("expected host for device-001 to be created")
	}
	if host.CanonicalHostname == "" {
		t.Error("expected non-empty hostname")
	}

	// Verify libraries for device-001.
	result, err := st.ListCryptoLibraries(context.Background(), store.LibrarySearchQuery{HostID: host.ID})
	if err != nil {
		t.Fatalf("ListCryptoLibraries: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	got := getLibsCount(result)
	if got < 2 {
		t.Errorf("expected at least 2 libraries for device-001, got %d", got)
	}

	// Verify cursor was advanced.
	state, err := st.GetIngestionState(context.Background(), SourceName)
	if err != nil {
		t.Fatalf("GetIngestionState: %v", err)
	}
	if state == nil || state.Cursor == "" {
		t.Error("expected cursor to be set after successful cycle")
	}
}

func TestPollerIntegration_ReingestNoOp(t *testing.T) {
	st := newTestStore(t)
	ing := ingest.NewUnifiedIngester(st)

	mock := NewMockClient()
	mock.Rows = loadResponseRows(t, "advanced_hunting_response.json")

	cfg := config.DefenderSourceConfig{}
	p := newPoller(mock, ing, st, cfg)

	// Run twice — second cycle re-ingests the same rows.
	for i := 0; i < 2; i++ {
		if err := p.runCycle(context.Background()); err != nil {
			t.Fatalf("runCycle %d: %v", i, err)
		}
	}

	host, err := st.FindHostBySourceID(context.Background(), "defender", "device-001")
	if err != nil || host == nil {
		t.Fatalf("device-001 host not found: %v", err)
	}

	result, err := st.ListCryptoLibraries(context.Background(), store.LibrarySearchQuery{HostID: host.ID})
	if err != nil {
		t.Fatalf("ListCryptoLibraries: %v", err)
	}
	got := getLibsCount(result)
	if got != 2 {
		t.Errorf("expected exactly 2 libraries for device-001 after re-ingest (dedup'd), got %d", got)
	}
}

// getLibsCount returns the number of libraries in a LibrarySearchResult.
// LibrarySearchResult uses the field name Libraries ([]model.CryptoLibrary).
func getLibsCount(result *store.LibrarySearchResult) int {
	if result == nil {
		return 0
	}
	return len(result.Libraries)
}
