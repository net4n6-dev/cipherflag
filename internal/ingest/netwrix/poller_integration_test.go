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

package netwrix

import (
	"context"
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/config"
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
	// Clean slate between tests.
	_, _ = st.Pool().Exec(context.Background(), "TRUNCATE ad_cs_events, ingestion_state")
	return st
}

func TestPollerIntegration_EndToEnd(t *testing.T) {
	st := newTestStore(t)

	mock := NewMockClient()
	mock.Records = []ActivityRecord{
		loadActivityRecord(t, "activity_record_issued.json"),
		loadActivityRecord(t, "activity_record_revoked.json"),
	}

	cfg := config.NetwrixSourceConfig{
		Enabled:             true,
		PollIntervalSeconds: 60,
	}
	p := newPoller(mock, st, cfg)

	if err := p.runCycle(context.Background()); err != nil {
		t.Fatalf("runCycle: %v", err)
	}

	// Verify events landed in the database.
	result, err := st.ListADCSEvents(context.Background(), store.ADCSEventQuery{
		CANames: []string{"corp-CA01-CA"},
	})
	if err != nil {
		t.Fatalf("ListADCSEvents: %v", err)
	}
	if len(result.Events) < 2 {
		t.Errorf("expected >= 2 events for corp-CA01-CA, got %d", len(result.Events))
	}

	// Verify cursor was advanced.
	state, err := st.GetIngestionState(context.Background(), SourceName)
	if err != nil {
		t.Fatalf("GetIngestionState: %v", err)
	}
	if state == nil || state.Cursor == "" {
		t.Errorf("expected cursor to be set after successful cycle")
	}
}

func TestPollerIntegration_ReingestIdempotent(t *testing.T) {
	st := newTestStore(t)

	mock := NewMockClient()
	mock.Records = []ActivityRecord{loadActivityRecord(t, "activity_record_issued.json")}

	cfg := config.NetwrixSourceConfig{}
	p := newPoller(mock, st, cfg)

	// First cycle: ingest the record.
	if err := p.runCycle(context.Background()); err != nil {
		t.Fatalf("runCycle 1: %v", err)
	}

	// Second cycle: same record. The deterministic UUID + ON CONFLICT DO NOTHING
	// should make this a no-op.
	if err := p.runCycle(context.Background()); err != nil {
		t.Fatalf("runCycle 2: %v", err)
	}

	// Count rows for the issued fixture's serial.
	result, err := st.ListADCSEvents(context.Background(), store.ADCSEventQuery{
		SerialNumber: "0a1b2c3d",
	})
	if err != nil {
		t.Fatalf("ListADCSEvents: %v", err)
	}
	count := 0
	for _, e := range result.Events {
		if e.SerialNumber == "0a1b2c3d" && e.CAName == "corp-CA01-CA" && e.EventType == "issued" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 row for the same logical event after re-ingest, got %d", count)
	}
}
