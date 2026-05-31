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

package absolute

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

// fakeStore implements the Store interface.
type fakeStore struct {
	mu    sync.Mutex
	state map[string]*model.IngestionState
}

func newFakeStore() *fakeStore { return &fakeStore{state: map[string]*model.IngestionState{}} }

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

func TestNewPoller_RejectsUnsupportedTrigger(t *testing.T) {
	cfg := config.AbsoluteSourceConfig{
		Enabled: true, TokenID: "t", SecretKey: "s", ConsoleURL: "https://x",
		Reach: config.AbsoluteReachConfig{Enabled: true, Trigger: "manual", Target: "all"},
	}
	_, err := NewPoller(NewMockClient(), &fakeIngester{}, newFakeStore(), cfg)
	if err == nil || !errors.Is(err, ErrUnsupportedReachTrigger) {
		t.Fatalf("want ErrUnsupportedReachTrigger, got %v", err)
	}
}

func TestNewPoller_RejectsUnsupportedTarget(t *testing.T) {
	cfg := config.AbsoluteSourceConfig{
		Enabled: true, TokenID: "t", SecretKey: "s", ConsoleURL: "https://x",
		Reach: config.AbsoluteReachConfig{Enabled: true, Trigger: "scheduled", Target: "group:prod"},
	}
	_, err := NewPoller(NewMockClient(), &fakeIngester{}, newFakeStore(), cfg)
	if err == nil || !errors.Is(err, ErrUnsupportedReachTarget) {
		t.Fatalf("want ErrUnsupportedReachTarget, got %v", err)
	}
}

func TestNewPoller_DefaultsIntervalsWhenZero(t *testing.T) {
	cfg := config.AbsoluteSourceConfig{
		Enabled: true, TokenID: "t", SecretKey: "s", ConsoleURL: "https://x",
		Inventory: config.AbsoluteInventoryConfig{Enabled: true},
		Reach:     config.AbsoluteReachConfig{Enabled: true, Trigger: "scheduled", Target: "all"},
	}
	p, err := NewPoller(NewMockClient(), &fakeIngester{}, newFakeStore(), cfg)
	if err != nil {
		t.Fatalf("NewPoller: %v", err)
	}
	if p.inventoryInterval != time.Hour {
		t.Errorf("inventoryInterval = %v, want 1h", p.inventoryInterval)
	}
	if p.reachInterval != 24*time.Hour {
		t.Errorf("reachInterval = %v, want 24h", p.reachInterval)
	}
}

func newTestPoller(t *testing.T, mock *MockClient, cfg config.AbsoluteSourceConfig) (*Poller, *fakeIngester, *fakeStore) {
	t.Helper()
	ing := &fakeIngester{}
	store := newFakeStore()
	p, err := NewPoller(mock, ing, store, cfg)
	if err != nil {
		t.Fatalf("NewPoller: %v", err)
	}
	return p, ing, store
}

func TestInventoryCycle_IngestsPerDeviceAndAdvancesCursor(t *testing.T) {
	mock := NewMockClient()
	mock.Apps = []DeviceApp{
		{DeviceID: "d1", DeviceName: "host-1", OSPlatform: "Linux", AppName: "OpenSSL", AppVersion: "3.0.14"},
		{DeviceID: "d1", DeviceName: "host-1", OSPlatform: "Linux", AppName: "GnuTLS", AppVersion: "3.7"},
		{DeviceID: "d2", DeviceName: "host-2", OSPlatform: "Windows", AppName: "BouncyCastle", AppVersion: "1.78"},
	}
	cfg := config.AbsoluteSourceConfig{
		Enabled: true, TokenID: "t", SecretKey: "s", ConsoleURL: "https://x",
		Inventory: config.AbsoluteInventoryConfig{Enabled: true, PollIntervalSeconds: 3600},
	}
	p, ing, store := newTestPoller(t, mock, cfg)

	if err := p.runInventoryCycle(context.Background()); err != nil {
		t.Fatalf("runInventoryCycle: %v", err)
	}
	if len(ing.Results) != 2 {
		t.Fatalf("ingested %d, want 2", len(ing.Results))
	}
	byHost := map[string]*ingest.DiscoveryResult{}
	for _, r := range ing.Results {
		byHost[r.SourceHostID] = r
	}
	if r := byHost["d1"]; r == nil || len(r.Libraries) != 2 {
		t.Errorf("d1 libraries = %+v", r)
	}
	if r := byHost["d2"]; r == nil || len(r.Libraries) != 1 {
		t.Errorf("d2 libraries = %+v", r)
	}
	st, _ := store.GetIngestionState(context.Background(), SourceNameInventory)
	if st == nil || st.Cursor == "" {
		t.Fatalf("cursor not advanced: %+v", st)
	}
	if _, err := time.Parse(time.RFC3339Nano, st.Cursor); err != nil {
		t.Errorf("cursor not RFC3339Nano: %q", st.Cursor)
	}
	if mock.AppCalls != 1 {
		t.Errorf("AppCalls = %d, want 1", mock.AppCalls)
	}
}

func TestInventoryCycle_RateLimitPreservesCursor(t *testing.T) {
	mock := NewMockClient()
	mock.AppErr = &RateLimitError{RetryAfter: 30 * time.Second}
	cfg := config.AbsoluteSourceConfig{
		Enabled: true, TokenID: "t", SecretKey: "s", ConsoleURL: "https://x",
		Inventory: config.AbsoluteInventoryConfig{Enabled: true},
	}
	p, _, store := newTestPoller(t, mock, cfg)

	if err := p.runInventoryCycle(context.Background()); err != nil {
		t.Fatalf("want nil for rate limit, got %v", err)
	}
	st, _ := store.GetIngestionState(context.Background(), SourceNameInventory)
	if st != nil {
		t.Errorf("cursor should not be set after rate limit, got %+v", st)
	}
}

func TestInventoryCycle_AuthErrorDisablesAdapter(t *testing.T) {
	mock := NewMockClient()
	mock.AppErr = &AuthError{StatusCode: 401, Body: "unauthorized"}
	cfg := config.AbsoluteSourceConfig{
		Enabled: true, TokenID: "t", SecretKey: "s", ConsoleURL: "https://x",
		Inventory: config.AbsoluteInventoryConfig{Enabled: true},
	}
	p, _, _ := newTestPoller(t, mock, cfg)

	if err := p.runInventoryCycle(context.Background()); err != nil {
		t.Fatalf("first cycle: %v", err)
	}
	if !p.isAuthDisabled() {
		t.Fatal("expected authDisabled after 401")
	}
	before := mock.AppCalls
	if err := p.runInventoryCycle(context.Background()); err != nil {
		t.Fatalf("second cycle: %v", err)
	}
	if mock.AppCalls != before {
		t.Errorf("client called while auth disabled")
	}
}

func TestReachCycle_LaunchesAllConfiguredScripts(t *testing.T) {
	mock := NewMockClient()
	mock.ExecuteExecutionID = "exec-launch"
	cfg := config.AbsoluteSourceConfig{
		Enabled: true, TokenID: "t", SecretKey: "s", ConsoleURL: "https://x",
		Reach: config.AbsoluteReachConfig{
			Enabled: true, Trigger: "scheduled", Target: "all",
			CertScriptID:      "c1",
			SSHKeysScriptID:   "s1",
			LibrariesScriptID: "l1",
			ConfigsScriptID:   "cf1",
		},
	}
	p, _, store := newTestPoller(t, mock, cfg)

	if err := p.runReachCycle(context.Background()); err != nil {
		t.Fatalf("runReachCycle: %v", err)
	}
	if len(mock.ExecuteCalls) != 4 {
		t.Errorf("ExecuteCalls = %d, want 4", len(mock.ExecuteCalls))
	}
	st, _ := store.GetIngestionState(context.Background(), SourceNameReach)
	if st == nil {
		t.Fatal("cursor not persisted")
	}
	cur, _ := UnmarshalReachCursor(st.Cursor)
	if len(cur.ActiveExecutions) != 4 {
		t.Errorf("active executions = %d, want 4", len(cur.ActiveExecutions))
	}
}

func TestReachCycle_PollsRunningTasksAndKeepsThemActive(t *testing.T) {
	mock := NewMockClient()
	mock.DefaultStatus = ReachTaskStatus{State: ReachTaskStateRunning}
	cfg := config.AbsoluteSourceConfig{
		Enabled: true, TokenID: "t", SecretKey: "s", ConsoleURL: "https://x",
		Reach: config.AbsoluteReachConfig{Enabled: true, Trigger: "scheduled", Target: "all"},
	}
	p, _, store := newTestPoller(t, mock, cfg)

	initial := &ReachCursor{
		ActiveExecutions: []ReachActiveExecution{{ScriptID: "c1", ExecutionID: "abc", LaunchedAt: time.Now()}},
		LastLaunchAt:     time.Now(),
	}
	raw, _ := initial.Marshal()
	_ = store.SetIngestionState(context.Background(), &model.IngestionState{SourceName: SourceNameReach, Cursor: raw, UpdatedAt: time.Now()})

	if err := p.runReachCycle(context.Background()); err != nil {
		t.Fatalf("runReachCycle: %v", err)
	}
	if len(mock.StatusCalls) != 1 {
		t.Errorf("StatusCalls = %d", len(mock.StatusCalls))
	}
	if len(mock.ResultCalls) != 0 {
		t.Errorf("ResultCalls = %d, want 0 while running", len(mock.ResultCalls))
	}
	st, _ := store.GetIngestionState(context.Background(), SourceNameReach)
	cur, _ := UnmarshalReachCursor(st.Cursor)
	if len(cur.ActiveExecutions) != 1 {
		t.Errorf("running task dropped: %+v", cur.ActiveExecutions)
	}
}

func TestReachCycle_CompletedTasksIngestAndClear(t *testing.T) {
	mock := NewMockClient()
	mock.DefaultStatus = ReachTaskStatus{State: ReachTaskStateCompleted}
	mock.Results["abc"] = []byte(`{"type":"library","name":"openssl","version":"3.0.14"}` + "\n")
	cfg := config.AbsoluteSourceConfig{
		Enabled: true, TokenID: "t", SecretKey: "s", ConsoleURL: "https://x",
		Reach: config.AbsoluteReachConfig{Enabled: true, Trigger: "scheduled", Target: "all"},
	}
	p, ing, store := newTestPoller(t, mock, cfg)

	initial := &ReachCursor{
		ActiveExecutions: []ReachActiveExecution{{ScriptID: "c1", ExecutionID: "abc", LaunchedAt: time.Now()}},
		LastLaunchAt:     time.Now(),
	}
	raw, _ := initial.Marshal()
	_ = store.SetIngestionState(context.Background(), &model.IngestionState{SourceName: SourceNameReach, Cursor: raw, UpdatedAt: time.Now()})

	if err := p.runReachCycle(context.Background()); err != nil {
		t.Fatalf("runReachCycle: %v", err)
	}
	if len(ing.Results) != 1 {
		t.Fatalf("ingested %d, want 1", len(ing.Results))
	}
	if len(ing.Results[0].Libraries) != 1 {
		t.Errorf("libraries = %d", len(ing.Results[0].Libraries))
	}
	st, _ := store.GetIngestionState(context.Background(), SourceNameReach)
	cur, _ := UnmarshalReachCursor(st.Cursor)
	if len(cur.ActiveExecutions) != 0 {
		t.Errorf("completed task not cleared: %+v", cur.ActiveExecutions)
	}
}

func TestReachCycle_FailedTasksAreDropped(t *testing.T) {
	mock := NewMockClient()
	mock.DefaultStatus = ReachTaskStatus{State: ReachTaskStateFailed, Detail: "script error"}
	cfg := config.AbsoluteSourceConfig{
		Enabled: true, TokenID: "t", SecretKey: "s", ConsoleURL: "https://x",
		Reach: config.AbsoluteReachConfig{Enabled: true, Trigger: "scheduled", Target: "all"},
	}
	p, ing, store := newTestPoller(t, mock, cfg)

	initial := &ReachCursor{
		ActiveExecutions: []ReachActiveExecution{{ScriptID: "c1", ExecutionID: "abc", LaunchedAt: time.Now()}},
		LastLaunchAt:     time.Now(),
	}
	raw, _ := initial.Marshal()
	_ = store.SetIngestionState(context.Background(), &model.IngestionState{SourceName: SourceNameReach, Cursor: raw, UpdatedAt: time.Now()})

	if err := p.runReachCycle(context.Background()); err != nil {
		t.Fatalf("runReachCycle: %v", err)
	}
	if len(ing.Results) != 0 {
		t.Errorf("ingested = %d, want 0 for failed task", len(ing.Results))
	}
	st, _ := store.GetIngestionState(context.Background(), SourceNameReach)
	cur, _ := UnmarshalReachCursor(st.Cursor)
	if len(cur.ActiveExecutions) != 0 {
		t.Errorf("failed task not dropped: %+v", cur.ActiveExecutions)
	}
}

func TestReachCycle_AuthErrorDisablesAdapter(t *testing.T) {
	mock := NewMockClient()
	mock.ExecuteErr = &AuthError{StatusCode: 403, Body: "forbidden"}
	cfg := config.AbsoluteSourceConfig{
		Enabled: true, TokenID: "t", SecretKey: "s", ConsoleURL: "https://x",
		Reach: config.AbsoluteReachConfig{
			Enabled: true, Trigger: "scheduled", Target: "all",
			CertScriptID: "c1",
		},
	}
	p, _, _ := newTestPoller(t, mock, cfg)

	if err := p.runReachCycle(context.Background()); err != nil {
		t.Fatalf("first cycle: %v", err)
	}
	if !p.isAuthDisabled() {
		t.Fatal("expected authDisabled after 403 on launch")
	}
	before := len(mock.ExecuteCalls)
	if err := p.runReachCycle(context.Background()); err != nil {
		t.Fatalf("second cycle: %v", err)
	}
	if len(mock.ExecuteCalls) != before {
		t.Errorf("client called while auth disabled")
	}
}
