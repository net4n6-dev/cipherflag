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

package absolute

import (
	"context"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/ingest"
	"github.com/net4n6-dev/cipherflag/internal/store"
	"github.com/net4n6-dev/cipherflag/internal/testdb"
)

func newIntegrationStore(t *testing.T) *store.PostgresStore {
	t.Helper()

	ctx := context.Background()
	st, err := store.NewPostgresStore(ctx, testdb.Require(t))
	if err != nil {
		t.Skipf("integration DB unavailable: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
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
	for _, tbl := range tables {
		if _, err := pool.Exec(ctx, "TRUNCATE TABLE "+tbl+" CASCADE"); err != nil {
			// Table may not exist in earlier migration states; ignore.
			_ = err
		}
	}
	return st
}

func TestIntegration_Absolute_Inventory_EndToEnd(t *testing.T) {
	st := newIntegrationStore(t)

	mock := NewMockClient()
	mock.Apps = []DeviceApp{
		{DeviceID: "abs-001", DeviceName: "web-01", OSPlatform: "Linux", AppName: "OpenSSL 3.0.14", AppVersion: "3.0.14"},
		{DeviceID: "abs-001", DeviceName: "web-01", OSPlatform: "Linux", AppName: "GnuTLS", AppVersion: "3.7.11"},
	}

	cfg := config.AbsoluteSourceConfig{
		Enabled: true, TokenID: "t", SecretKey: "s", ConsoleURL: "https://x",
		Inventory: config.AbsoluteInventoryConfig{Enabled: true, PollIntervalSeconds: 3600},
	}
	ingr := ingest.NewUnifiedIngester(st)
	p, err := NewPoller(mock, ingr, st, cfg)
	if err != nil {
		t.Fatalf("NewPoller: %v", err)
	}

	if err := p.runInventoryCycle(context.Background()); err != nil {
		t.Fatalf("runInventoryCycle: %v", err)
	}

	state, err := st.GetIngestionState(context.Background(), SourceNameInventory)
	if err != nil {
		t.Fatalf("GetIngestionState: %v", err)
	}
	if state == nil || state.Cursor == "" {
		t.Fatalf("cursor not advanced: %+v", state)
	}
	if _, err := time.Parse(time.RFC3339Nano, state.Cursor); err != nil {
		t.Errorf("cursor not RFC3339Nano: %q", state.Cursor)
	}

	var libCount int
	if err := st.Pool().QueryRow(context.Background(), `SELECT COUNT(*) FROM crypto_libraries`).Scan(&libCount); err != nil {
		t.Fatalf("query libraries: %v", err)
	}
	if libCount < 2 {
		t.Errorf("crypto_libraries = %d, want >=2", libCount)
	}
}

func TestIntegration_Absolute_Reach_EndToEnd(t *testing.T) {
	st := newIntegrationStore(t)

	mock := NewMockClient()
	mock.ExecuteExecutionID = "exec-001"
	mock.DefaultStatus = ReachTaskStatus{State: ReachTaskStateCompleted}
	mock.Results["exec-001"] = []byte(`{"type":"library","name":"openssl","version":"3.0.14"}` + "\n")

	cfg := config.AbsoluteSourceConfig{
		Enabled: true, TokenID: "t", SecretKey: "s", ConsoleURL: "https://x",
		Reach: config.AbsoluteReachConfig{
			Enabled: true, Trigger: "scheduled", Target: "all",
			CertScriptID: "c1",
		},
	}
	ingr := ingest.NewUnifiedIngester(st)
	p, err := NewPoller(mock, ingr, st, cfg)
	if err != nil {
		t.Fatalf("NewPoller: %v", err)
	}

	// Cycle 1 launches.
	if err := p.runReachCycle(context.Background()); err != nil {
		t.Fatalf("launch cycle: %v", err)
	}
	// Cycle 2 ingests completed.
	if err := p.runReachCycle(context.Background()); err != nil {
		t.Fatalf("ingest cycle: %v", err)
	}

	state, err := st.GetIngestionState(context.Background(), SourceNameReach)
	if err != nil {
		t.Fatalf("GetIngestionState: %v", err)
	}
	if state == nil {
		t.Fatal("reach cursor missing")
	}
	cur, err := UnmarshalReachCursor(state.Cursor)
	if err != nil {
		t.Fatalf("UnmarshalReachCursor: %v", err)
	}
	if len(cur.ActiveExecutions) != 0 {
		t.Errorf("active executions after ingest = %+v", cur.ActiveExecutions)
	}
	var libCount int
	if err := st.Pool().QueryRow(context.Background(), `SELECT COUNT(*) FROM crypto_libraries`).Scan(&libCount); err != nil {
		t.Fatalf("query libraries: %v", err)
	}
	if libCount < 1 {
		t.Errorf("crypto_libraries = %d, want >=1", libCount)
	}
}

func TestIntegration_Absolute_AuthErrorDisablesAdapter(t *testing.T) {
	st := newIntegrationStore(t)

	mock := NewMockClient()
	mock.AppErr = &AuthError{StatusCode: 401, Body: "unauthorized"}

	cfg := config.AbsoluteSourceConfig{
		Enabled: true, TokenID: "t", SecretKey: "s", ConsoleURL: "https://x",
		Inventory: config.AbsoluteInventoryConfig{Enabled: true},
	}
	ingr := ingest.NewUnifiedIngester(st)
	p, err := NewPoller(mock, ingr, st, cfg)
	if err != nil {
		t.Fatalf("NewPoller: %v", err)
	}

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
