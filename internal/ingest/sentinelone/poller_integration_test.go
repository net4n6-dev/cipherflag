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

package sentinelone

import (
	"context"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/ingest"
	"github.com/net4n6-dev/cipherflag/internal/store"
	"github.com/net4n6-dev/cipherflag/internal/testdb"
)

// newIntegrationStore connects to the test DB, runs migrations, and truncates
// all relevant tables. The test is skipped if CIPHERFLAG_TEST_DB is not set.
func newIntegrationStore(t *testing.T) *store.PostgresStore {
	t.Helper()

	dsn := testdb.Require(t)

	ctx := context.Background()

	st, err := store.NewPostgresStore(ctx, dsn)
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate test db: %v", err)
	}

	tables := []string{
		"asset_provenance",
		"asset_health_reports",
		"agent_tokens",
		"protocol_observations",
		"crypto_configs",
		"crypto_libraries",
		"ssh_keys",
		"host_identifiers",
		"observations",
		"endpoint_profiles",
		"health_reports",
		"ingestion_state",
		"pcap_jobs",
		"certificates",
		"hosts",
		"users",
	}
	pool := st.Pool()
	for _, table := range tables {
		if _, err := pool.Exec(ctx, "TRUNCATE TABLE "+table+" CASCADE"); err != nil {
			// Table may not exist in earlier migration states; ignore.
			_ = err
		}
	}

	return st
}

// TestIntegration_AppInventory_EndToEnd loads the MockClient with 2 AppRecords
// for one agent, runs one App Inventory cycle, and asserts:
//   - cursor persisted in RFC3339Nano format
//   - both libraries persisted for the host
func TestIntegration_AppInventory_EndToEnd(t *testing.T) {
	st := newIntegrationStore(t)
	ctx := context.Background()

	ing := ingest.NewUnifiedIngester(st)

	mock := NewMockClient()
	mock.AppRecords = []AppRecord{
		{AgentUUID: "agent-aa", AgentName: "web-01", OSType: "linux", AppName: "OpenSSL", AppVersion: "3.0.14"},
		{AgentUUID: "agent-aa", AgentName: "web-01", OSType: "linux", AppName: "GnuTLS", AppVersion: "3.7.9"},
	}

	cfg := config.SentinelOneSourceConfig{
		Enabled:      true,
		AppInventory: config.SentinelOneAppInventoryConfig{Enabled: true, PollIntervalSeconds: 3600},
	}
	p, err := NewPoller(mock, ing, st, cfg)
	if err != nil {
		t.Fatalf("NewPoller: %v", err)
	}

	if err := p.runAppInventoryCycle(ctx); err != nil {
		t.Fatalf("runAppInventoryCycle: %v", err)
	}

	// Assert cursor persisted in RFC3339Nano format.
	state, err := st.GetIngestionState(ctx, SourceNameAppInventory)
	if err != nil {
		t.Fatalf("GetIngestionState: %v", err)
	}
	if state == nil || state.Cursor == "" {
		t.Fatal("expected cursor to be set after successful cycle")
	}
	if _, err := time.Parse(time.RFC3339Nano, state.Cursor); err != nil {
		t.Errorf("cursor is not RFC3339Nano: %q", state.Cursor)
	}

	// Assert host was created.
	host, err := st.FindHostBySourceID(ctx, SourceName, "agent-aa")
	if err != nil {
		t.Fatalf("FindHostBySourceID: %v", err)
	}
	if host == nil {
		t.Fatal("expected host for agent-aa to be created")
	}

	// Assert both libraries persisted for the host.
	result, err := st.ListCryptoLibraries(ctx, store.LibrarySearchQuery{HostID: host.ID, Limit: 10})
	if err != nil {
		t.Fatalf("ListCryptoLibraries: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil library result")
	}
	if len(result.Libraries) < 2 {
		t.Errorf("expected at least 2 libraries for web-01, got %d", len(result.Libraries))
	}
}

// TestIntegration_RSO_EndToEnd seeds the MockClient with an ExecuteTaskID and
// a completed status, runs the RSO cycle twice (first launches, second ingests),
// and asserts:
//   - cursor has 0 active tasks after completion
//   - library result was ingested
func TestIntegration_RSO_EndToEnd(t *testing.T) {
	st := newIntegrationStore(t)
	ctx := context.Background()

	ing := ingest.NewUnifiedIngester(st)

	const taskID = "rso-task-int-001"
	mock := NewMockClient()
	mock.ExecuteTaskID = taskID
	// First call returns running so the first cycle (which launches) is
	// followed by a second cycle that sees completed.
	mock.DefaultStatus = TaskStatus{State: TaskStateCompleted}
	mock.Results[taskID] = []byte(`{"type":"library","name":"openssl","version":"3.0.14","package_name":"openssl","package_manager":"apt","install_path":"/usr/lib/libssl.so.3"}` + "\n")

	cfg := config.SentinelOneSourceConfig{
		Enabled: true,
		RSO: config.SentinelOneRSOConfig{
			Enabled:           true,
			Trigger:           "scheduled",
			Target:            "all",
			LibrariesScriptID: "script-libs",
		},
	}
	p, err := NewPoller(mock, ing, st, cfg)
	if err != nil {
		t.Fatalf("NewPoller: %v", err)
	}

	// Cycle 1: no active tasks, last launch zero — should launch scripts and
	// persist cursor with 1 active task.
	if err := p.runRSOCycle(ctx); err != nil {
		t.Fatalf("runRSOCycle (launch): %v", err)
	}

	stateAfterLaunch, err := st.GetIngestionState(ctx, SourceNameRSO)
	if err != nil {
		t.Fatalf("GetIngestionState after launch: %v", err)
	}
	if stateAfterLaunch == nil {
		t.Fatal("expected RSO cursor to be set after launch cycle")
	}
	cursorAfterLaunch, err := UnmarshalRSOCursor(stateAfterLaunch.Cursor)
	if err != nil {
		t.Fatalf("UnmarshalRSOCursor after launch: %v", err)
	}
	if len(cursorAfterLaunch.ActiveTasks) == 0 {
		t.Fatal("expected at least 1 active task after launch cycle")
	}

	// Cycle 2: active tasks present, status = completed — should ingest
	// results and clear the task from the cursor.
	if err := p.runRSOCycle(ctx); err != nil {
		t.Fatalf("runRSOCycle (ingest): %v", err)
	}

	stateAfterIngest, err := st.GetIngestionState(ctx, SourceNameRSO)
	if err != nil {
		t.Fatalf("GetIngestionState after ingest: %v", err)
	}
	if stateAfterIngest == nil {
		t.Fatal("expected RSO cursor to be set after ingest cycle")
	}
	cursorAfterIngest, err := UnmarshalRSOCursor(stateAfterIngest.Cursor)
	if err != nil {
		t.Fatalf("UnmarshalRSOCursor after ingest: %v", err)
	}
	if len(cursorAfterIngest.ActiveTasks) != 0 {
		t.Errorf("expected 0 active tasks after completed ingest, got %d: %+v",
			len(cursorAfterIngest.ActiveTasks), cursorAfterIngest.ActiveTasks)
	}

	// Assert at least 1 library was ingested. The RSO path keys the result
	// by task ID, so we query directly via the pool.
	pool := st.Pool()
	var libCount int
	err = pool.QueryRow(ctx, `SELECT COUNT(*) FROM crypto_libraries`).Scan(&libCount)
	if err != nil {
		t.Fatalf("count crypto_libraries: %v", err)
	}
	if libCount < 1 {
		t.Errorf("expected at least 1 library ingested from RSO results, got %d", libCount)
	}
}
