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

package tanium

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

func TestIntegration_Tanium_EndToEnd(t *testing.T) {
	st := newIntegrationStore(t)
	mock := NewMockClient()
	mock.Page = EndpointPage{
		Endpoints: []EndpointResult{
			{
				EndpointID: "ep-001", Hostname: "web-01", IPAddress: "10.0.1.10", OSPlatform: "Linux",
				Sensors: []SensorReading{
					{
						SensorName: "CipherFlag.Crypto.Libraries",
						Columns: []SensorColumn{{Name: "output", Values: []string{
							`{"type":"library","name":"openssl","version":"3.0.14"}`,
						}}},
					},
					{
						SensorName: "Installed Applications",
						Columns: []SensorColumn{
							{Name: "Name", Values: []string{"GnuTLS"}},
							{Name: "Version", Values: []string{"3.7.11"}},
							{Name: "Publisher", Values: []string{"GnuTLS"}},
						},
					},
				},
			},
		},
	}

	cfg := config.TaniumSourceConfig{Enabled: true, APIToken: "t", ConsoleURL: "https://x"}
	ingr := ingest.NewUnifiedIngester(st)
	p := NewPoller(mock, ingr, st, cfg)

	if err := p.runCycle(context.Background()); err != nil {
		t.Fatalf("runCycle: %v", err)
	}

	// Cursor advanced in RFC3339Nano.
	state, err := st.GetIngestionState(context.Background(), SourceName)
	if err != nil {
		t.Fatalf("GetIngestionState: %v", err)
	}
	if state == nil || state.Cursor == "" {
		t.Fatalf("cursor not advanced: %+v", state)
	}
	if _, err := time.Parse(time.RFC3339Nano, state.Cursor); err != nil {
		t.Errorf("cursor not RFC3339Nano: %q", state.Cursor)
	}

	// Libraries persisted (openssl from custom sensor + gnutls from Installed Applications).
	pool := st.Pool()
	var libCount int
	if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM crypto_libraries`).Scan(&libCount); err != nil {
		t.Fatalf("query libraries: %v", err)
	}
	if libCount < 2 {
		t.Errorf("crypto_libraries = %d, want >=2", libCount)
	}
}

func TestIntegration_Tanium_Pagination(t *testing.T) {
	st := newIntegrationStore(t)
	mock := NewMockClient()
	mock.Pages = []EndpointPage{
		{
			Endpoints: []EndpointResult{
				{EndpointID: "e1", Hostname: "h1", IPAddress: "10.0.0.1", OSPlatform: "Linux",
					Sensors: []SensorReading{{SensorName: "CipherFlag.Crypto.Libraries",
						Columns: []SensorColumn{{Name: "output", Values: []string{`{"type":"library","name":"openssl","version":"3.0.14"}`}}}}},
				},
			},
			HasNext: true, EndCursor: "c1",
		},
		{
			Endpoints: []EndpointResult{
				{EndpointID: "e2", Hostname: "h2", IPAddress: "10.0.0.2", OSPlatform: "Linux",
					Sensors: []SensorReading{{SensorName: "CipherFlag.Crypto.Libraries",
						Columns: []SensorColumn{{Name: "output", Values: []string{`{"type":"library","name":"gnutls","version":"3.7.11"}`}}}}},
				},
			},
			HasNext: false,
		},
	}

	cfg := config.TaniumSourceConfig{Enabled: true, APIToken: "t", ConsoleURL: "https://x"}
	ingr := ingest.NewUnifiedIngester(st)
	p := NewPoller(mock, ingr, st, cfg)

	if err := p.runCycle(context.Background()); err != nil {
		t.Fatalf("runCycle: %v", err)
	}
	if mock.CallCount != 2 {
		t.Errorf("CallCount = %d, want 2", mock.CallCount)
	}

	pool := st.Pool()
	var hostCount int
	if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM hosts`).Scan(&hostCount); err != nil {
		t.Fatalf("query hosts: %v", err)
	}
	if hostCount != 2 {
		t.Errorf("hosts = %d, want 2", hostCount)
	}
}

func TestIntegration_Tanium_AuthErrorDisablesAdapter(t *testing.T) {
	st := newIntegrationStore(t)
	mock := NewMockClient()
	mock.Err = &AuthError{StatusCode: 401, Body: "bad token"}

	cfg := config.TaniumSourceConfig{Enabled: true, APIToken: "t", ConsoleURL: "https://x"}
	ingr := ingest.NewUnifiedIngester(st)
	p := NewPoller(mock, ingr, st, cfg)

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
		t.Errorf("client called while disabled")
	}
}
