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

package store

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/testdb"
)

func newTestScanJob(t *testing.T) (*PostgresStore, string, func()) {
	t.Helper()
	dsn := testdb.Require(t)
	ctx := context.Background()
	s, err := NewPostgresStore(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if _, err := s.pool.Exec(ctx, "TRUNCATE scan_jobs, repositories, providers CASCADE"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	prov := &model.Provider{Kind: "github", BaseURL: "https://github.com", AuthSecretRef: "env:X"}
	if err := s.UpsertProvider(ctx, prov); err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	repo := &model.Repository{ProviderID: prov.ID, URL: "https://github.com/a/b", DefaultBranch: "main", DefaultScanMode: "enrichment"}
	if err := s.UpsertRepository(ctx, repo); err != nil {
		t.Fatalf("seed repo: %v", err)
	}
	return s, repo.ID, func() {
		_, _ = s.pool.Exec(ctx, "TRUNCATE scan_jobs, repositories, providers CASCADE")
		s.Close()
	}
}

func TestEnqueueScanJob_Defaults(t *testing.T) {
	s, repoID, done := newTestScanJob(t)
	defer done()
	ctx := context.Background()

	j := &model.ScanJob{
		RepoID:    repoID,
		ScanMode:  model.ScanModeDeterministicOnly,
		Trigger:   model.TriggerManual,
		BranchRef: "main",
	}
	if err := s.EnqueueScanJob(ctx, j); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if j.ID == "" {
		t.Fatal("expected ID populated")
	}
	got, err := s.GetScanJob(ctx, j.ID)
	if err != nil || got == nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != model.ScanStatusQueued {
		t.Errorf("want status queued, got %q", got.Status)
	}
	if got.CreatedAt.IsZero() {
		t.Error("expected created_at populated")
	}
}

func TestClaimScanJob_NoQueuedReturnsNil(t *testing.T) {
	s, _, done := newTestScanJob(t)
	defer done()
	ctx := context.Background()

	got, err := s.ClaimScanJob(ctx, "worker-1")
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil on empty queue, got %+v", got)
	}
}

func TestClaimScanJob_FIFO(t *testing.T) {
	s, repoID, done := newTestScanJob(t)
	defer done()
	ctx := context.Background()

	j1 := &model.ScanJob{RepoID: repoID, ScanMode: model.ScanModeDeterministicOnly, Trigger: model.TriggerManual, BranchRef: "main"}
	if err := s.EnqueueScanJob(ctx, j1); err != nil {
		t.Fatalf("enq1: %v", err)
	}
	j2 := &model.ScanJob{RepoID: repoID, ScanMode: model.ScanModeDeterministicOnly, Trigger: model.TriggerManual, BranchRef: "feat/x"}
	if err := s.EnqueueScanJob(ctx, j2); err != nil {
		t.Fatalf("enq2: %v", err)
	}

	first, err := s.ClaimScanJob(ctx, "w-1")
	if err != nil || first == nil {
		t.Fatalf("claim1: %v", err)
	}
	if first.ID != j1.ID {
		t.Errorf("FIFO violated: expected j1=%s, got %s", j1.ID, first.ID)
	}
	if first.Status != model.ScanStatusRunning {
		t.Errorf("want running, got %q", first.Status)
	}
	if first.WorkerID != "w-1" {
		t.Errorf("want worker w-1, got %q", first.WorkerID)
	}
	if first.StartedAt == nil {
		t.Error("want started_at populated")
	}

	second, err := s.ClaimScanJob(ctx, "w-2")
	if err != nil || second == nil {
		t.Fatalf("claim2: %v", err)
	}
	if second.ID != j2.ID {
		t.Errorf("second claim should be j2=%s, got %s", j2.ID, second.ID)
	}
}

func TestClaimScanJob_SKIP_LOCKED_RaceSafe(t *testing.T) {
	s, repoID, done := newTestScanJob(t)
	defer done()
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		j := &model.ScanJob{RepoID: repoID, ScanMode: model.ScanModeDeterministicOnly, Trigger: model.TriggerManual, BranchRef: "main"}
		if err := s.EnqueueScanJob(ctx, j); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	claimed := map[string]string{}

	for w := 0; w < 3; w++ {
		workerID := "worker-" + string(rune('A'+w))
		wg.Add(1)
		go func(wid string) {
			defer wg.Done()
			for {
				j, err := s.ClaimScanJob(ctx, wid)
				if err != nil {
					t.Errorf("claim: %v", err)
					return
				}
				if j == nil {
					return
				}
				mu.Lock()
				if other, dup := claimed[j.ID]; dup {
					t.Errorf("job %s claimed twice: %s and %s", j.ID, other, wid)
				}
				claimed[j.ID] = wid
				mu.Unlock()
			}
		}(workerID)
	}
	wg.Wait()

	if len(claimed) != 10 {
		t.Errorf("want 10 claims, got %d", len(claimed))
	}
}

func TestUpdateScanJob_CompletionPath(t *testing.T) {
	s, repoID, done := newTestScanJob(t)
	defer done()
	ctx := context.Background()

	j := &model.ScanJob{RepoID: repoID, ScanMode: model.ScanModeDeterministicOnly, Trigger: model.TriggerManual, BranchRef: "main"}
	if err := s.EnqueueScanJob(ctx, j); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	claimed, err := s.ClaimScanJob(ctx, "w")
	if err != nil || claimed == nil {
		t.Fatalf("claim: %v", err)
	}
	claimed.Status = model.ScanStatusCompleted
	claimed.FindingsCount = 0
	claimed.SummaryJSON = map[string]any{"blobs_scanned": 100, "blobs_cache_hit": 0}
	if err := s.UpdateScanJob(ctx, claimed); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, _ := s.GetScanJob(ctx, claimed.ID)
	if got.Status != model.ScanStatusCompleted {
		t.Errorf("want completed, got %q", got.Status)
	}
	if got.CompletedAt == nil {
		t.Error("want completed_at populated on terminal status")
	}
	if got.SummaryJSON["blobs_scanned"].(float64) != 100 {
		t.Error("summary_json not persisted")
	}
}

func TestCancelScanJob_QueuedOnly(t *testing.T) {
	s, repoID, done := newTestScanJob(t)
	defer done()
	ctx := context.Background()

	j := &model.ScanJob{RepoID: repoID, ScanMode: model.ScanModeDeterministicOnly, Trigger: model.TriggerManual, BranchRef: "main"}
	if err := s.EnqueueScanJob(ctx, j); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if err := s.CancelScanJob(ctx, j.ID); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	got, _ := s.GetScanJob(ctx, j.ID)
	if got.Status != model.ScanStatusCancelled {
		t.Errorf("want cancelled, got %q", got.Status)
	}

	running := &model.ScanJob{RepoID: repoID, ScanMode: model.ScanModeDeterministicOnly, Trigger: model.TriggerManual, BranchRef: "main"}
	if err := s.EnqueueScanJob(ctx, running); err != nil {
		t.Fatalf("enqueue running: %v", err)
	}
	if _, err := s.ClaimScanJob(ctx, "w"); err != nil {
		t.Fatalf("claim running: %v", err)
	}
	if err := s.CancelScanJob(ctx, running.ID); err != nil {
		t.Fatalf("cancel running: %v", err)
	}
	gotRunning, _ := s.GetScanJob(ctx, running.ID)
	if gotRunning.Status != model.ScanStatusRunning {
		t.Errorf("cancelling a running job should be a no-op in v1; got status %q", gotRunning.Status)
	}
}

// TestClaimScanJob_RespectsNextRetryAt verifies Layer 6.2a retry gating:
// a queued job whose next_retry_at is in the future is NOT claimable.
// Once next_retry_at has passed, the same job IS claimable, and its
// retry_count round-trips through the claim.
func TestClaimScanJob_RespectsNextRetryAt(t *testing.T) {
	s, repoID, done := newTestScanJob(t)
	defer done()
	ctx := context.Background()

	future := time.Now().Add(1 * time.Hour)
	j := &model.ScanJob{
		RepoID:      repoID,
		ScanMode:    model.ScanModeDeterministicOnly,
		Trigger:     model.TriggerManual,
		BranchRef:   "main",
		RetryCount:  2,
		NextRetryAt: &future,
	}
	if err := s.EnqueueScanJob(ctx, j); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	// Future next_retry_at: claim must return nil.
	if claimed, err := s.ClaimScanJob(ctx, "w-1"); err != nil {
		t.Fatalf("claim (future): %v", err)
	} else if claimed != nil {
		t.Fatalf("expected nil claim when next_retry_at is future, got %+v", claimed)
	}

	// Move next_retry_at into the past (directly via SQL — UpdateScanJob
	// would also stomp retry_count/failure_class, and we specifically want
	// to assert retry_count round-trips from claim).
	past := time.Now().Add(-1 * time.Minute)
	if _, err := s.pool.Exec(ctx, `UPDATE scan_jobs SET next_retry_at = $1 WHERE id = $2`, past, j.ID); err != nil {
		t.Fatalf("shift next_retry_at: %v", err)
	}

	claimed, err := s.ClaimScanJob(ctx, "w-1")
	if err != nil {
		t.Fatalf("claim (past): %v", err)
	}
	if claimed == nil {
		t.Fatal("expected claim to succeed after next_retry_at passed")
	}
	if claimed.ID != j.ID {
		t.Errorf("claimed wrong job: want %s, got %s", j.ID, claimed.ID)
	}
	if claimed.RetryCount != 2 {
		t.Errorf("retry_count not round-tripped: want 2, got %d", claimed.RetryCount)
	}
}

// TestUpdateScanJob_WritesFailureClass verifies that setting FailureClass
// on a scan job and calling UpdateScanJob persists the value, and GetScanJob
// returns it faithfully.
func TestUpdateScanJob_WritesFailureClass(t *testing.T) {
	s, repoID, done := newTestScanJob(t)
	defer done()
	ctx := context.Background()

	j := &model.ScanJob{
		RepoID:    repoID,
		ScanMode:  model.ScanModeDeterministicOnly,
		Trigger:   model.TriggerManual,
		BranchRef: "main",
	}
	if err := s.EnqueueScanJob(ctx, j); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	claimed, err := s.ClaimScanJob(ctx, "w")
	if err != nil || claimed == nil {
		t.Fatalf("claim: %v", err)
	}

	claimed.Status = model.ScanStatusFailed
	claimed.FailureClass = model.FailureClassAuth
	claimed.ErrorText = "registry returned 401"
	if err := s.UpdateScanJob(ctx, claimed); err != nil {
		t.Fatalf("update: %v", err)
	}

	got, err := s.GetScanJob(ctx, claimed.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("expected row, got nil")
	}
	if got.FailureClass != model.FailureClassAuth {
		t.Errorf("failure_class not persisted: want %q, got %q", model.FailureClassAuth, got.FailureClass)
	}
	if got.Status != model.ScanStatusFailed {
		t.Errorf("status not persisted: want %q, got %q", model.ScanStatusFailed, got.Status)
	}
}
