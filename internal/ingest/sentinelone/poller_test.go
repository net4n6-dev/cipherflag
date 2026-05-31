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
package sentinelone

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

// fakeStore implements the Store interface used by the poller.
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

// fakeIngester implements ingest.Ingester for tests.
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
	cfg := config.SentinelOneSourceConfig{
		Enabled: true, APIToken: "t", ConsoleURL: "https://x",
		RSO: config.SentinelOneRSOConfig{Enabled: true, Trigger: "manual", Target: "all"},
	}
	_, err := NewPoller(NewMockClient(), &fakeIngester{}, newFakeStore(), cfg)
	if err == nil || !errors.Is(err, ErrUnsupportedRSOTrigger) {
		t.Fatalf("want ErrUnsupportedRSOTrigger, got %v", err)
	}
}

func TestNewPoller_RejectsUnsupportedTarget(t *testing.T) {
	cfg := config.SentinelOneSourceConfig{
		Enabled: true, APIToken: "t", ConsoleURL: "https://x",
		RSO: config.SentinelOneRSOConfig{Enabled: true, Trigger: "scheduled", Target: "group:prod"},
	}
	_, err := NewPoller(NewMockClient(), &fakeIngester{}, newFakeStore(), cfg)
	if err == nil || !errors.Is(err, ErrUnsupportedRSOTarget) {
		t.Fatalf("want ErrUnsupportedRSOTarget, got %v", err)
	}
}

func TestNewPoller_DefaultsIntervalsWhenZero(t *testing.T) {
	cfg := config.SentinelOneSourceConfig{
		Enabled: true, APIToken: "t", ConsoleURL: "https://x",
		AppInventory: config.SentinelOneAppInventoryConfig{Enabled: true},
		RSO:          config.SentinelOneRSOConfig{Enabled: true, Trigger: "scheduled", Target: "all"},
	}
	p, err := NewPoller(NewMockClient(), &fakeIngester{}, newFakeStore(), cfg)
	if err != nil {
		t.Fatalf("NewPoller: %v", err)
	}
	if p.appInterval != time.Hour {
		t.Errorf("appInterval = %v, want 1h", p.appInterval)
	}
	if p.rsoInterval != 24*time.Hour {
		t.Errorf("rsoInterval = %v, want 24h", p.rsoInterval)
	}
}

func newTestPoller(t *testing.T, mock *MockClient, cfg config.SentinelOneSourceConfig) (*Poller, *fakeIngester, *fakeStore) {
	t.Helper()
	ing := &fakeIngester{}
	store := newFakeStore()
	p, err := NewPoller(mock, ing, store, cfg)
	if err != nil {
		t.Fatalf("NewPoller: %v", err)
	}
	return p, ing, store
}

func TestAppInventoryCycle_IngestsPerAgentAndAdvancesCursor(t *testing.T) {
	mock := NewMockClient()
	mock.AppRecords = []AppRecord{
		{AgentUUID: "u1", AgentName: "host-1", OSType: "linux", AppName: "OpenSSL", AppVersion: "3.0.14"},
		{AgentUUID: "u1", AgentName: "host-1", OSType: "linux", AppName: "GnuTLS", AppVersion: "3.7"},
		{AgentUUID: "u2", AgentName: "host-2", OSType: "windows", AppName: "BouncyCastle", AppVersion: "1.78"},
	}
	cfg := config.SentinelOneSourceConfig{
		Enabled: true, APIToken: "t", ConsoleURL: "https://x",
		AppInventory: config.SentinelOneAppInventoryConfig{Enabled: true, PollIntervalSeconds: 3600},
	}
	p, ing, store := newTestPoller(t, mock, cfg)

	if err := p.runAppInventoryCycle(context.Background()); err != nil {
		t.Fatalf("runAppInventoryCycle: %v", err)
	}

	if len(ing.Results) != 2 {
		t.Fatalf("ingested %d results, want 2", len(ing.Results))
	}
	byHost := map[string]*ingest.DiscoveryResult{}
	for _, r := range ing.Results {
		byHost[r.SourceHostID] = r
	}
	if r := byHost["u1"]; r == nil || len(r.Libraries) != 2 {
		t.Errorf("u1 libraries = %+v", r)
	}
	if r := byHost["u2"]; r == nil || len(r.Libraries) != 1 {
		t.Errorf("u2 libraries = %+v", r)
	}
	st, _ := store.GetIngestionState(context.Background(), SourceNameAppInventory)
	if st == nil || st.Cursor == "" {
		t.Fatalf("cursor not advanced: %+v", st)
	}
	if _, err := time.Parse(time.RFC3339Nano, st.Cursor); err != nil {
		t.Errorf("cursor not RFC3339Nano: %q", st.Cursor)
	}
	if mock.AppCalls != 1 {
		t.Errorf("AppCalls = %d", mock.AppCalls)
	}
}

func TestAppInventoryCycle_RateLimitPreservesCursor(t *testing.T) {
	mock := NewMockClient()
	mock.AppErr = &RateLimitError{RetryAfter: 30 * time.Second}
	cfg := config.SentinelOneSourceConfig{
		Enabled: true, APIToken: "t", ConsoleURL: "https://x",
		AppInventory: config.SentinelOneAppInventoryConfig{Enabled: true},
	}
	p, _, store := newTestPoller(t, mock, cfg)

	if err := p.runAppInventoryCycle(context.Background()); err != nil {
		t.Fatalf("runAppInventoryCycle returned non-nil for rate limit: %v", err)
	}
	st, _ := store.GetIngestionState(context.Background(), SourceNameAppInventory)
	if st != nil {
		t.Errorf("cursor should not be set after rate limit, got %+v", st)
	}
}

func TestRSOCycle_LaunchesAllConfiguredScripts(t *testing.T) {
	mock := NewMockClient()
	mock.ExecuteTaskID = "task-launch"
	cfg := config.SentinelOneSourceConfig{
		Enabled: true, APIToken: "t", ConsoleURL: "https://x",
		RSO: config.SentinelOneRSOConfig{
			Enabled: true, Trigger: "scheduled", Target: "all",
			CertScriptID:        "c1",
			SSHKeysScriptID:     "s1",
			LibrariesScriptID:   "l1",
			ConfigFilesScriptID: "cf1",
			CertFilesScriptID:   "cert1",
		},
	}
	p, _, store := newTestPoller(t, mock, cfg)

	// No active tasks and no prior launch — cycle should launch all 5.
	if err := p.runRSOCycle(context.Background()); err != nil {
		t.Fatalf("runRSOCycle: %v", err)
	}
	if len(mock.ExecuteCalls) != 5 {
		t.Errorf("ExecuteCalls = %d, want 5", len(mock.ExecuteCalls))
	}
	st, _ := store.GetIngestionState(context.Background(), SourceNameRSO)
	if st == nil {
		t.Fatal("cursor not persisted")
	}
	cur, _ := UnmarshalRSOCursor(st.Cursor)
	if len(cur.ActiveTasks) != 5 {
		t.Errorf("active tasks = %d, want 5", len(cur.ActiveTasks))
	}
}

func TestRSOCycle_PollsRunningTasksAndKeepsThemActive(t *testing.T) {
	mock := NewMockClient()
	mock.DefaultStatus = TaskStatus{State: TaskStateRunning}
	cfg := config.SentinelOneSourceConfig{
		Enabled: true, APIToken: "t", ConsoleURL: "https://x",
		RSO: config.SentinelOneRSOConfig{Enabled: true, Trigger: "scheduled", Target: "all"},
	}
	p, _, store := newTestPoller(t, mock, cfg)

	// Seed cursor with one active task.
	initial := &RSOCursor{
		ActiveTasks:  []RSOActiveTask{{ScriptID: "c1", TaskID: "abc", LaunchedAt: time.Now()}},
		LastLaunchAt: time.Now(),
	}
	raw, _ := initial.Marshal()
	_ = store.SetIngestionState(context.Background(), &model.IngestionState{SourceName: SourceNameRSO, Cursor: raw, UpdatedAt: time.Now()})

	if err := p.runRSOCycle(context.Background()); err != nil {
		t.Fatalf("runRSOCycle: %v", err)
	}
	if len(mock.StatusCalls) != 1 {
		t.Errorf("StatusCalls = %d", len(mock.StatusCalls))
	}
	if len(mock.ResultCalls) != 0 {
		t.Errorf("ResultCalls = %d, want 0 while running", len(mock.ResultCalls))
	}
	st, _ := store.GetIngestionState(context.Background(), SourceNameRSO)
	cur, _ := UnmarshalRSOCursor(st.Cursor)
	if len(cur.ActiveTasks) != 1 {
		t.Errorf("running task dropped: %+v", cur.ActiveTasks)
	}
}

func TestRSOCycle_CompletedTasksIngestAndClear(t *testing.T) {
	mock := NewMockClient()
	mock.DefaultStatus = TaskStatus{State: TaskStateCompleted}
	mock.Results["abc"] = []byte(`{"type":"library","name":"openssl","version":"3.0.14"}` + "\n")
	cfg := config.SentinelOneSourceConfig{
		Enabled: true, APIToken: "t", ConsoleURL: "https://x",
		RSO: config.SentinelOneRSOConfig{Enabled: true, Trigger: "scheduled", Target: "all"},
	}
	p, ing, store := newTestPoller(t, mock, cfg)

	initial := &RSOCursor{
		ActiveTasks:  []RSOActiveTask{{ScriptID: "c1", TaskID: "abc", LaunchedAt: time.Now()}},
		LastLaunchAt: time.Now(),
	}
	raw, _ := initial.Marshal()
	_ = store.SetIngestionState(context.Background(), &model.IngestionState{SourceName: SourceNameRSO, Cursor: raw, UpdatedAt: time.Now()})

	if err := p.runRSOCycle(context.Background()); err != nil {
		t.Fatalf("runRSOCycle: %v", err)
	}
	if len(ing.Results) != 1 {
		t.Fatalf("ingested %d, want 1", len(ing.Results))
	}
	if len(ing.Results[0].Libraries) != 1 {
		t.Errorf("libraries = %d", len(ing.Results[0].Libraries))
	}
	st, _ := store.GetIngestionState(context.Background(), SourceNameRSO)
	cur, _ := UnmarshalRSOCursor(st.Cursor)
	if len(cur.ActiveTasks) != 0 {
		t.Errorf("completed task not cleared: %+v", cur.ActiveTasks)
	}
}

func TestAppInventoryCycle_AuthErrorDisablesAdapter(t *testing.T) {
	mock := NewMockClient()
	mock.AppErr = &AuthError{StatusCode: 401, Body: "unauthorized"}
	cfg := config.SentinelOneSourceConfig{
		Enabled: true, APIToken: "t", ConsoleURL: "https://x",
		AppInventory: config.SentinelOneAppInventoryConfig{Enabled: true},
	}
	p, _, _ := newTestPoller(t, mock, cfg)

	if err := p.runAppInventoryCycle(context.Background()); err != nil {
		t.Fatalf("first cycle: %v", err)
	}
	if !p.isAuthDisabled() {
		t.Fatal("expected authDisabled after 401")
	}

	// Second cycle should short-circuit without calling the client.
	before := mock.AppCalls
	if err := p.runAppInventoryCycle(context.Background()); err != nil {
		t.Fatalf("second cycle: %v", err)
	}
	if mock.AppCalls != before {
		t.Errorf("client called while auth disabled (before=%d, after=%d)", before, mock.AppCalls)
	}
}

func TestRSOCycle_AuthErrorDisablesAdapter(t *testing.T) {
	mock := NewMockClient()
	mock.ExecuteErr = &AuthError{StatusCode: 403, Body: "forbidden"}
	cfg := config.SentinelOneSourceConfig{
		Enabled: true, APIToken: "t", ConsoleURL: "https://x",
		RSO: config.SentinelOneRSOConfig{
			Enabled: true, Trigger: "scheduled", Target: "all",
			CertScriptID: "c1",
		},
	}
	p, _, _ := newTestPoller(t, mock, cfg)

	if err := p.runRSOCycle(context.Background()); err != nil {
		t.Fatalf("first cycle: %v", err)
	}
	if !p.isAuthDisabled() {
		t.Fatal("expected authDisabled after 403 on launch")
	}

	// Second cycle short-circuits.
	before := len(mock.ExecuteCalls)
	if err := p.runRSOCycle(context.Background()); err != nil {
		t.Fatalf("second cycle: %v", err)
	}
	if len(mock.ExecuteCalls) != before {
		t.Errorf("client called while auth disabled")
	}
}

func TestRSOCycle_FailedTasksAreDropped(t *testing.T) {
	mock := NewMockClient()
	mock.DefaultStatus = TaskStatus{State: TaskStateFailed, Detail: "script error"}
	cfg := config.SentinelOneSourceConfig{
		Enabled: true, APIToken: "t", ConsoleURL: "https://x",
		RSO: config.SentinelOneRSOConfig{Enabled: true, Trigger: "scheduled", Target: "all"},
	}
	p, ing, store := newTestPoller(t, mock, cfg)

	initial := &RSOCursor{
		ActiveTasks:  []RSOActiveTask{{ScriptID: "c1", TaskID: "abc", LaunchedAt: time.Now()}},
		LastLaunchAt: time.Now(),
	}
	raw, _ := initial.Marshal()
	_ = store.SetIngestionState(context.Background(), &model.IngestionState{SourceName: SourceNameRSO, Cursor: raw, UpdatedAt: time.Now()})

	if err := p.runRSOCycle(context.Background()); err != nil {
		t.Fatalf("runRSOCycle: %v", err)
	}
	if len(ing.Results) != 0 {
		t.Errorf("ingested = %d, want 0 for failed task", len(ing.Results))
	}
	st, _ := store.GetIngestionState(context.Background(), SourceNameRSO)
	cur, _ := UnmarshalRSOCursor(st.Cursor)
	if len(cur.ActiveTasks) != 0 {
		t.Errorf("failed task not dropped: %+v", cur.ActiveTasks)
	}
}
