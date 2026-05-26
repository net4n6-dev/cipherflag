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

package scheduler

import (
	"context"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

type fakeStore struct {
	repos     []model.Repository
	enqueued  []*model.ScanJob
	lastAt    map[string]time.Time
	activeJob map[string]bool
}

func (f *fakeStore) ListScheduledRepos(ctx context.Context) ([]model.Repository, error) {
	return f.repos, nil
}
func (f *fakeStore) EnqueueScanJob(ctx context.Context, j *model.ScanJob) error {
	f.enqueued = append(f.enqueued, j)
	return nil
}
func (f *fakeStore) UpdateRepositoryLastScheduledAt(ctx context.Context, id string, when time.Time) error {
	if f.lastAt == nil {
		f.lastAt = map[string]time.Time{}
	}
	f.lastAt[id] = when
	return nil
}
func (f *fakeStore) HasActiveScanJob(ctx context.Context, repoID string) (bool, error) {
	return f.activeJob[repoID], nil
}

func TestScheduler_EnqueuesDueRepo(t *testing.T) {
	r := model.Repository{
		ID:              "r-1",
		ScheduleCron:    "* * * * *",
		DefaultBranch:   "main",
		DefaultScanMode: "deterministic_only",
	}
	f := &fakeStore{repos: []model.Repository{r}, activeJob: map[string]bool{}}
	s := &Scheduler{Store: f, Now: func() time.Time { return time.Unix(1_700_000_123, 0).UTC() }}

	if err := s.RunOnce(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(f.enqueued) != 1 {
		t.Errorf("want 1 enqueued, got %d", len(f.enqueued))
	}
	if f.enqueued[0].Trigger != model.TriggerScheduled {
		t.Errorf("trigger: %q", f.enqueued[0].Trigger)
	}
}

func TestScheduler_SkipsRepoWithActiveScan(t *testing.T) {
	r := model.Repository{ID: "r-1", ScheduleCron: "* * * * *", DefaultBranch: "main", DefaultScanMode: "deterministic_only"}
	f := &fakeStore{repos: []model.Repository{r}, activeJob: map[string]bool{"r-1": true}}
	s := &Scheduler{Store: f, Now: time.Now}

	_ = s.RunOnce(context.Background())
	if len(f.enqueued) != 0 {
		t.Error("should skip repo with running scan")
	}
}

func TestScheduler_HonoursLastScheduledAt(t *testing.T) {
	now := time.Unix(1_700_000_123, 0).UTC()
	lastFired := now.Add(-30 * time.Second) // 30s ago
	r := model.Repository{
		ID:              "r-1",
		ScheduleCron:    "0 */6 * * *", // every 6 hours
		DefaultBranch:   "main",
		DefaultScanMode: "deterministic_only",
		LastScheduledAt: &lastFired,
	}
	f := &fakeStore{repos: []model.Repository{r}, activeJob: map[string]bool{}}
	s := &Scheduler{Store: f, Now: func() time.Time { return now }}

	_ = s.RunOnce(context.Background())
	if len(f.enqueued) != 0 {
		t.Error("6-hourly schedule shouldn't re-fire 30s after last fire")
	}
}
