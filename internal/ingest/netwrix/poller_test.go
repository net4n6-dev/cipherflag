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
package netwrix

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/model"
)

// fakeStore captures inserted events and tracks ingestion state.
type fakeStore struct {
	mu            sync.Mutex
	BatchedEvents [][]*model.ADCSEvent
	State         *model.IngestionState
	BatchErr      error
	GetStateErr   error
	SetStateErr   error
}

func (f *fakeStore) BatchRecordADCSEvents(_ context.Context, events []*model.ADCSEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.BatchErr != nil {
		return f.BatchErr
	}
	f.BatchedEvents = append(f.BatchedEvents, events)
	return nil
}

func (f *fakeStore) GetIngestionState(_ context.Context, _ string) (*model.IngestionState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.GetStateErr != nil {
		return nil, f.GetStateErr
	}
	return f.State, nil
}

func (f *fakeStore) SetIngestionState(_ context.Context, state *model.IngestionState) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.SetStateErr != nil {
		return f.SetStateErr
	}
	f.State = state
	return nil
}

func TestPoller_RunCycle_BasicFlow(t *testing.T) {
	mock := NewMockClient()
	mock.Records = []ActivityRecord{
		loadActivityRecord(t, "activity_record_issued.json"),
		loadActivityRecord(t, "activity_record_revoked.json"),
	}

	st := &fakeStore{}
	cfg := config.NetwrixSourceConfig{
		Enabled:             true,
		PollIntervalSeconds: 60,
	}
	p := newPoller(mock, st, cfg)

	if err := p.runCycle(context.Background()); err != nil {
		t.Fatalf("runCycle: %v", err)
	}

	if len(st.BatchedEvents) != 1 {
		t.Fatalf("expected 1 batch, got %d", len(st.BatchedEvents))
	}
	if len(st.BatchedEvents[0]) != 2 {
		t.Errorf("batch should contain 2 events, got %d", len(st.BatchedEvents[0]))
	}
	if st.State == nil || st.State.SourceName != "netwrix:ad_cs" {
		t.Errorf("expected ingestion state set with source netwrix:ad_cs, got %+v", st.State)
	}
}

func TestPoller_RunCycle_NoRecords(t *testing.T) {
	mock := NewMockClient() // empty Records
	st := &fakeStore{}
	cfg := config.NetwrixSourceConfig{}
	p := newPoller(mock, st, cfg)

	if err := p.runCycle(context.Background()); err != nil {
		t.Fatalf("runCycle: %v", err)
	}
	if len(st.BatchedEvents) != 0 {
		t.Errorf("expected 0 batches when no records, got %d", len(st.BatchedEvents))
	}
}

func TestPoller_RunCycle_BatchErrorPreservesCursor(t *testing.T) {
	mock := NewMockClient()
	mock.Records = []ActivityRecord{loadActivityRecord(t, "activity_record_issued.json")}

	originalCursor := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	st := &fakeStore{
		State: &model.IngestionState{
			SourceName: "netwrix:ad_cs",
			Cursor:     originalCursor,
		},
		BatchErr: errors.New("db down"),
	}
	cfg := config.NetwrixSourceConfig{}
	p := newPoller(mock, st, cfg)

	err := p.runCycle(context.Background())
	if err == nil {
		t.Fatal("expected error from runCycle when batch fails")
	}
	if st.State.Cursor != originalCursor {
		t.Errorf("cursor advanced despite batch failure: got %q, want %q", st.State.Cursor, originalCursor)
	}
}

func TestPoller_RunCycle_SkipsMalformedRecord(t *testing.T) {
	mock := NewMockClient()
	mock.Records = []ActivityRecord{
		loadActivityRecord(t, "activity_record_issued.json"),
		// Malformed: missing serial number.
		{Raw: map[string]interface{}{"Action": "Added", "ObjectType": "Certificate", "Where": "ca"}},
	}

	st := &fakeStore{}
	cfg := config.NetwrixSourceConfig{}
	p := newPoller(mock, st, cfg)

	if err := p.runCycle(context.Background()); err != nil {
		t.Fatalf("runCycle: %v", err)
	}
	if len(st.BatchedEvents) != 1 || len(st.BatchedEvents[0]) != 1 {
		t.Errorf("expected 1 valid event batched (malformed skipped), got batches=%v", st.BatchedEvents)
	}
}

func TestPoller_Run_Cancellation(t *testing.T) {
	mock := NewMockClient()
	st := &fakeStore{}
	cfg := config.NetwrixSourceConfig{PollIntervalSeconds: 1}
	p := NewPoller(mock, st, cfg)

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
