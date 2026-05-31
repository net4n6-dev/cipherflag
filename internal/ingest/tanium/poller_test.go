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
package tanium

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/ingest"
	"github.com/net4n6-dev/cipherflag/internal/model"
)

type fakeStore struct {
	mu    sync.Mutex
	state map[string]*model.IngestionState
}

func newFakeStore() *fakeStore {
	return &fakeStore{state: map[string]*model.IngestionState{}}
}

func (f *fakeStore) GetIngestionState(_ context.Context, name string) (*model.IngestionState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.state[name], nil
}

func (f *fakeStore) SetIngestionState(_ context.Context, s *model.IngestionState) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state[s.SourceName] = s
	return nil
}

type fakeIngester struct {
	mu      sync.Mutex
	Results []*ingest.DiscoveryResult
	Err     error
}

func (f *fakeIngester) Ingest(_ context.Context, r *ingest.DiscoveryResult) (*ingest.IngestionSummary, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Err != nil {
		return nil, f.Err
	}
	f.Results = append(f.Results, r)
	return &ingest.IngestionSummary{HostID: "host-" + r.SourceHostID}, nil
}

func (f *fakeIngester) AttributeAssets(_ context.Context, claims []ingest.OwnershipClaim) (emitted, skipped int, err error) {
	return len(claims), 0, nil
}

func TestNewPoller_DefaultsIntervalWhenZero(t *testing.T) {
	cfg := config.TaniumSourceConfig{
		Enabled: true, APIToken: "t", ConsoleURL: "https://x",
	}
	p := NewPoller(NewMockClient(), &fakeIngester{}, newFakeStore(), cfg)
	if p.interval != time.Hour {
		t.Errorf("interval = %v, want 1h", p.interval)
	}
}

func newTestPoller(t *testing.T, mock *MockClient, cfg config.TaniumSourceConfig) (*Poller, *fakeIngester, *fakeStore) {
	t.Helper()
	ing := &fakeIngester{}
	store := newFakeStore()
	p := NewPoller(mock, ing, store, cfg)
	return p, ing, store
}

func TestRunCycle_SinglePage_IngestsPerEndpointAndAdvancesCursor(t *testing.T) {
	mock := NewMockClient()
	mock.Page = EndpointPage{
		Endpoints: []EndpointResult{
			{EndpointID: "e1", Hostname: "h1", IPAddress: "10.0.0.1", OSPlatform: "Linux",
				Sensors: []SensorReading{{
					SensorName: "CipherFlag.Crypto.Libraries",
					Columns:    []SensorColumn{{Name: "output", Values: []string{`{"type":"library","name":"openssl","version":"3.0.14"}`}}},
				}}},
			{EndpointID: "e2", Hostname: "h2", IPAddress: "10.0.0.2", OSPlatform: "Windows",
				Sensors: []SensorReading{{
					SensorName: "Installed Applications",
					Columns: []SensorColumn{
						{Name: "Name", Values: []string{"OpenSSL"}},
						{Name: "Version", Values: []string{"1.1.1"}},
						{Name: "Publisher", Values: []string{"OpenSSL Project"}},
					},
				}}},
		},
		HasNext: false,
	}
	cfg := config.TaniumSourceConfig{Enabled: true, APIToken: "t", ConsoleURL: "https://x", PollIntervalSeconds: 3600}
	p, ing, store := newTestPoller(t, mock, cfg)

	if err := p.runCycle(context.Background()); err != nil {
		t.Fatalf("runCycle: %v", err)
	}
	if len(ing.Results) != 2 {
		t.Fatalf("ingested %d, want 2", len(ing.Results))
	}
	if mock.CallCount != 1 {
		t.Errorf("CallCount = %d, want 1", mock.CallCount)
	}
	st, _ := store.GetIngestionState(context.Background(), SourceName)
	if st == nil || st.Cursor == "" {
		t.Fatalf("cursor not advanced: %+v", st)
	}
	if _, err := time.Parse(time.RFC3339Nano, st.Cursor); err != nil {
		t.Errorf("cursor not RFC3339Nano: %q", st.Cursor)
	}
}

func TestRunCycle_MultiPagePagination(t *testing.T) {
	mock := NewMockClient()
	mock.Pages = []EndpointPage{
		{
			Endpoints: []EndpointResult{
				{EndpointID: "e1", Hostname: "h1", OSPlatform: "Linux"},
			},
			HasNext:   true,
			EndCursor: "cursor-1",
		},
		{
			Endpoints: []EndpointResult{
				{EndpointID: "e2", Hostname: "h2", OSPlatform: "Linux"},
				{EndpointID: "e3", Hostname: "h3", OSPlatform: "Linux"},
			},
			HasNext:   true,
			EndCursor: "cursor-2",
		},
		{
			Endpoints: []EndpointResult{
				{EndpointID: "e4", Hostname: "h4", OSPlatform: "Linux"},
			},
			HasNext: false,
		},
	}
	cfg := config.TaniumSourceConfig{Enabled: true, APIToken: "t", ConsoleURL: "https://x"}
	p, ing, _ := newTestPoller(t, mock, cfg)

	if err := p.runCycle(context.Background()); err != nil {
		t.Fatalf("runCycle: %v", err)
	}
	if mock.CallCount != 3 {
		t.Errorf("CallCount = %d, want 3", mock.CallCount)
	}
	if len(ing.Results) != 4 {
		t.Errorf("ingested %d, want 4", len(ing.Results))
	}
	if mock.LastAfter != "cursor-2" {
		t.Errorf("LastAfter = %q, want cursor-2", mock.LastAfter)
	}
}

func TestRunCycle_RateLimitPreservesCursor(t *testing.T) {
	mock := NewMockClient()
	mock.Err = &RateLimitError{RetryAfter: 30 * time.Second}
	cfg := config.TaniumSourceConfig{Enabled: true, APIToken: "t", ConsoleURL: "https://x"}
	p, _, store := newTestPoller(t, mock, cfg)

	if err := p.runCycle(context.Background()); err != nil {
		t.Fatalf("want nil for rate limit, got %v", err)
	}
	st, _ := store.GetIngestionState(context.Background(), SourceName)
	if st != nil {
		t.Errorf("cursor should not be set after rate limit, got %+v", st)
	}
}

func TestRunCycle_AuthErrorDisablesAdapter(t *testing.T) {
	mock := NewMockClient()
	mock.Err = &AuthError{StatusCode: 401, Body: "unauthorized"}
	cfg := config.TaniumSourceConfig{Enabled: true, APIToken: "t", ConsoleURL: "https://x"}
	p, _, _ := newTestPoller(t, mock, cfg)

	if err := p.runCycle(context.Background()); err != nil {
		t.Fatalf("first cycle: %v", err)
	}
	if !p.isAuthDisabled() {
		t.Fatal("expected authDisabled after 401")
	}

	before := mock.CallCount
	if err := p.runCycle(context.Background()); err != nil {
		t.Fatalf("second cycle: %v", err)
	}
	if mock.CallCount != before {
		t.Errorf("client called while auth disabled (before=%d, after=%d)", before, mock.CallCount)
	}
}

func TestRunCycle_QueryErrorPreservesCursor(t *testing.T) {
	mock := NewMockClient()
	mock.Err = errorString("boom")
	cfg := config.TaniumSourceConfig{Enabled: true, APIToken: "t", ConsoleURL: "https://x"}
	p, _, store := newTestPoller(t, mock, cfg)

	if err := p.runCycle(context.Background()); err == nil {
		t.Fatal("expected error for 500")
	}
	st, _ := store.GetIngestionState(context.Background(), SourceName)
	if st != nil {
		t.Errorf("cursor should not be set after query error, got %+v", st)
	}
}

type errorString string

func (e errorString) Error() string { return string(e) }
