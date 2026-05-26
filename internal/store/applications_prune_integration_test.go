//go:build integration

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
	"testing"
	"time"
)

// TestPruneApplicationPostureSnapshotsOlderThan_DeletesOldRetainsNew
// pins the v1.3.6 retention contract against a real Postgres:
//
//   - Rows with captured_at < cutoff are deleted.
//   - Rows with captured_at >= cutoff survive.
//   - Return value matches the number of rows actually removed.
//
// Uses a unique tag so the test is isolated from any other data in
// the table (snapshots don't have a truncate cascade in testStore's
// table list, so parallel runs must not collide).
func TestPruneApplicationPostureSnapshotsOlderThan_DeletesOldRetainsNew(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	tag := "prune-test-" + time.Now().Format("150405.000")

	now := time.Now().UTC()
	// Three snapshots: 40d old, 10d old, 1d old. Cutoff at now-30d.
	// After prune: 40d-old row deleted, 10d + 1d rows retained.
	for _, age := range []time.Duration{40 * 24 * time.Hour, 10 * 24 * time.Hour, 1 * 24 * time.Hour} {
		snap := &ApplicationPostureSnapshot{
			Tag:            tag,
			CapturedAt:     now.Add(-age),
			CompositeGrade: "B",
			AverageScore:   80,
			TotalAssets:    2,
			ScoredAssets:   2,
			FindingCount:   3,
		}
		if err := st.SaveApplicationPostureSnapshot(ctx, snap); err != nil {
			t.Fatalf("seed snapshot age=%v: %v", age, err)
		}
	}

	cutoff := now.Add(-30 * 24 * time.Hour)
	deleted, err := st.PruneApplicationPostureSnapshotsOlderThan(ctx, cutoff)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if deleted != 1 {
		t.Errorf("deleted = %d, want 1 (only the 40d-old row)", deleted)
	}

	// Verify survivors via ListApplicationSnapshots — asserts the exact
	// remaining rows without requiring direct pool access.
	since := now.Add(-60 * 24 * time.Hour) // wide enough to catch anything
	remaining, err := st.ListApplicationSnapshots(ctx, tag, since)
	if err != nil {
		t.Fatalf("list remaining: %v", err)
	}
	if len(remaining) != 2 {
		t.Errorf("remaining = %d rows, want 2", len(remaining))
	}
	for _, r := range remaining {
		if r.CapturedAt.Before(cutoff) {
			t.Errorf("row survived pruning despite captured_at=%v < cutoff=%v", r.CapturedAt, cutoff)
		}
	}

	// Idempotency — second prune with same cutoff deletes nothing.
	deleted2, err := st.PruneApplicationPostureSnapshotsOlderThan(ctx, cutoff)
	if err != nil {
		t.Fatalf("prune2: %v", err)
	}
	if deleted2 != 0 {
		t.Errorf("idempotency broken: second prune deleted %d rows", deleted2)
	}

	t.Cleanup(func() {
		_, _ = st.pool.Exec(ctx, `DELETE FROM application_posture_snapshots WHERE tag = $1`, tag)
	})
}

// TestPruneApplicationPostureSnapshotsOlderThan_EmptyTableSucceeds
// pins that prune against an empty (or tag-absent) table returns
// (0, nil) rather than erroring. A fresh deployment calls this on
// every runner tick before any snapshot exists.
func TestPruneApplicationPostureSnapshotsOlderThan_EmptyTableSucceeds(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	// Use a clearly-future cutoff so ANY existing rows in the table
	// from other tests would be deleted — then re-seed them. Safer:
	// use a narrowly-past cutoff that wouldn't delete anything the
	// runner is actually writing day-to-day. now-10y is safely
	// older than any reasonable snapshot.
	cutoff := time.Now().Add(-10 * 365 * 24 * time.Hour)
	deleted, err := st.PruneApplicationPostureSnapshotsOlderThan(ctx, cutoff)
	if err != nil {
		t.Fatalf("prune on 10y-cutoff: %v", err)
	}
	if deleted != 0 {
		t.Errorf("10y-old cutoff should leave all rows; deleted %d", deleted)
	}
}
