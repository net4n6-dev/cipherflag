// Copyright 2026 net4n6-dev
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package defender

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/ingest"
	"github.com/net4n6-dev/cipherflag/internal/model"
)

// fakeIngester captures Ingest calls so tests can assert on the result.
type fakeIngester struct {
	mu      sync.Mutex
	results []*ingest.DiscoveryResult
	err     error
}

func (f *fakeIngester) Ingest(_ context.Context, r *ingest.DiscoveryResult) (*ingest.IngestionSummary, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.results = append(f.results, r)
	if f.err != nil {
		return nil, f.err
	}
	return &ingest.IngestionSummary{}, nil
}

func (f *fakeIngester) AttributeAssets(_ context.Context, claims []ingest.OwnershipClaim) (emitted, skipped int, err error) {
	return len(claims), 0, nil
}

// fakeStore implements the Store interface (subset of CryptoStore).
type fakeStore struct {
	mu          sync.Mutex
	state       *model.IngestionState
	getStateErr error
	setStateErr error
}

func (f *fakeStore) GetIngestionState(_ context.Context, _ string) (*model.IngestionState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getStateErr != nil {
		return nil, f.getStateErr
	}
	return f.state, nil
}

func (f *fakeStore) SetIngestionState(_ context.Context, state *model.IngestionState) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.setStateErr != nil {
		return f.setStateErr
	}
	f.state = state
	return nil
}

func TestPoller_RunCycle_BasicFlow_TwoDevices(t *testing.T) {
	mock := NewMockClient()
	mock.Rows = loadResponseRows(t, "advanced_hunting_response.json")

	st := &fakeStore{}
	ing := &fakeIngester{}
	cfg := config.DefenderSourceConfig{Enabled: true, PollIntervalSeconds: 60}
	p := newPoller(mock, ing, st, cfg)

	if err := p.runCycle(context.Background()); err != nil {
		t.Fatalf("runCycle: %v", err)
	}

	// Fixture has 2 devices (device-001 with 2 libs, device-002 with 1 lib) -> 2 ingest calls.
	if len(ing.results) != 2 {
		t.Fatalf("expected 2 ingest calls (one per device), got %d", len(ing.results))
	}

	// Find device-001 result and verify it has 2 libraries.
	var d1 *ingest.DiscoveryResult
	for _, r := range ing.results {
		if r.SourceHostID == "device-001" {
			d1 = r
			break
		}
	}
	if d1 == nil {
		t.Fatal("device-001 result not found")
	}
	if d1.Source != "defender" {
		t.Errorf("Source = %q", d1.Source)
	}
	if len(d1.Libraries) != 2 {
		t.Errorf("device-001 should have 2 libraries, got %d", len(d1.Libraries))
	}

	// Cursor advanced.
	if st.state == nil || st.state.SourceName != "defender:libraries" {
		t.Errorf("expected ingestion state set with source defender:libraries, got %+v", st.state)
	}
}

func TestPoller_RunCycle_NoRows(t *testing.T) {
	mock := NewMockClient() // empty Rows
	ing := &fakeIngester{}
	st := &fakeStore{}
	p := newPoller(mock, ing, st, config.DefenderSourceConfig{})

	if err := p.runCycle(context.Background()); err != nil {
		t.Fatalf("runCycle: %v", err)
	}
	if len(ing.results) != 0 {
		t.Errorf("expected no ingest calls, got %d", len(ing.results))
	}
	// Cursor still advances on empty result so we don't replay forever.
	if st.state == nil {
		t.Error("expected cursor to advance even with no rows")
	}
}

func TestPoller_RunCycle_QueryErrorPreservesCursor(t *testing.T) {
	mock := NewMockClient()
	mock.Err = errors.New("api down")

	originalCursor := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	st := &fakeStore{state: &model.IngestionState{SourceName: "defender:libraries", Cursor: originalCursor}}
	ing := &fakeIngester{}

	p := newPoller(mock, ing, st, config.DefenderSourceConfig{})
	err := p.runCycle(context.Background())
	if err == nil {
		t.Fatal("expected error from runCycle when query fails")
	}
	if st.state.Cursor != originalCursor {
		t.Errorf("cursor advanced despite query failure: got %q, want %q", st.state.Cursor, originalCursor)
	}
}

func TestPoller_RunCycle_RateLimitPreservesCursor(t *testing.T) {
	mock := NewMockClient()
	mock.Err = &RateLimitError{RetryAfter: 30 * time.Second}

	originalCursor := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	st := &fakeStore{state: &model.IngestionState{SourceName: "defender:libraries", Cursor: originalCursor}}
	ing := &fakeIngester{}

	p := newPoller(mock, ing, st, config.DefenderSourceConfig{})
	if err := p.runCycle(context.Background()); err != nil {
		t.Fatalf("runCycle should not return error on rate limit: %v", err)
	}
	if st.state.Cursor != originalCursor {
		t.Errorf("cursor advanced despite rate limit: got %q, want %q", st.state.Cursor, originalCursor)
	}
}

func TestPoller_RunCycle_PerDeviceIngestFailureContinues(t *testing.T) {
	mock := NewMockClient()
	mock.Rows = loadResponseRows(t, "advanced_hunting_response.json")

	st := &fakeStore{}
	ing := &fakeIngester{err: errors.New("ingest broke")}

	p := newPoller(mock, ing, st, config.DefenderSourceConfig{})
	if err := p.runCycle(context.Background()); err != nil {
		t.Fatalf("runCycle: %v", err)
	}
	// Despite errors, both devices were attempted.
	if len(ing.results) != 2 {
		t.Errorf("expected 2 ingest attempts even with errors, got %d", len(ing.results))
	}
	// Cursor still advances - query succeeded; per-device failures don't block.
	if st.state == nil {
		t.Error("expected cursor to advance after successful query (even with per-device ingest failures)")
	}
}

func TestPoller_Run_Cancellation(t *testing.T) {
	mock := NewMockClient()
	st := &fakeStore{}
	ing := &fakeIngester{}
	cfg := config.DefenderSourceConfig{PollIntervalSeconds: 1}
	p := NewPoller(mock, ing, st, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		p.Run(ctx)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancellation")
	}
}
