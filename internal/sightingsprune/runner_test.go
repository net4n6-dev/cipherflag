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

// Ported from CipherFlag EE (internal/sightingsprune). CE has no
// user_ip_sightings table, so the user-sightings case is dropped.

package sightingsprune

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeStore records every cutoff the runner passes and lets the test
// choose whether Prune succeeds or errors. Concurrent-safe because the
// Run goroutine may call Prune while the test inspects state.
type fakeStore struct {
	mu      sync.Mutex
	cutoffs []time.Time
	deleted int64
	err     error
	calls   int64
}

func (f *fakeStore) PruneHostIPSightings(_ context.Context, cutoff time.Time) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	atomic.AddInt64(&f.calls, 1)
	f.cutoffs = append(f.cutoffs, cutoff)
	return f.deleted, f.err
}

func (f *fakeStore) callCount() int64 { return atomic.LoadInt64(&f.calls) }

func (f *fakeStore) lastCutoff() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.cutoffs) == 0 {
		return time.Time{}
	}
	return f.cutoffs[len(f.cutoffs)-1]
}

// TestPrune_CutoffMath pins the 7-day retention math. A runner with
// default retention using a fixed clock must pass `now - 7d` to the
// store.
func TestPrune_CutoffMath(t *testing.T) {
	f := &fakeStore{}
	frozen := time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC)
	r := NewRunner(f, 24*time.Hour).WithClock(func() time.Time { return frozen })

	r.Prune(context.Background())

	if f.callCount() != 1 {
		t.Fatalf("calls = %d, want 1", f.callCount())
	}
	if got, want := f.lastCutoff(), frozen.Add(-7*24*time.Hour); !got.Equal(want) {
		t.Errorf("cutoff = %v, want %v", got, want)
	}
}

// TestPrune_WithRetention_Override confirms WithRetention(N) overrides
// the default and drives the cutoff math.
func TestPrune_WithRetention_Override(t *testing.T) {
	f := &fakeStore{}
	frozen := time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC)
	r := NewRunner(f, 24*time.Hour).
		WithRetention(30).
		WithClock(func() time.Time { return frozen })

	r.Prune(context.Background())

	if !f.lastCutoff().Equal(frozen.Add(-30 * 24 * time.Hour)) {
		t.Errorf("cutoff = %v, want now-30d", f.lastCutoff())
	}
}

// TestPrune_ZeroRetention_NoOp: retainDays <= 0 is the documented opt-out.
// Prune must not hit the store at all.
func TestPrune_ZeroRetention_NoOp(t *testing.T) {
	for _, retention := range []int{0, -1, -365} {
		f := &fakeStore{}
		NewRunner(f, 24*time.Hour).WithRetention(retention).Prune(context.Background())
		if f.callCount() != 0 {
			t.Errorf("retention=%d called store %d times; want 0", retention, f.callCount())
		}
	}
}

// TestPrune_StoreError_Swallowed confirms the "housekeeping, not
// correctness" contract: a Prune error is logged but never returned or
// panicked. The runner keeps going.
func TestPrune_StoreError_Swallowed(t *testing.T) {
	f := &fakeStore{err: errors.New("pg connection died")}
	NewRunner(f, 24*time.Hour).Prune(context.Background())
	if f.callCount() != 1 {
		t.Errorf("calls = %d, want 1 (error must not short-circuit)", f.callCount())
	}
}

func waitForCalls(f *fakeStore, n int64, budget time.Duration) {
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) && f.callCount() < n {
		time.Sleep(5 * time.Millisecond)
	}
}

// TestRun_StartupPrune_ImmediatelyFires: Run must prune once on start
// without waiting for the ticker, so a post-restart gap doesn't breach the
// retention contract.
func TestRun_StartupPrune_ImmediatelyFires(t *testing.T) {
	f := &fakeStore{}
	r := NewRunner(f, time.Hour) // interval far longer than the test

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()

	waitForCalls(f, 1, time.Second)
	cancel()
	<-done
	if f.callCount() != 1 {
		t.Fatalf("startup calls = %d, want 1", f.callCount())
	}
}

// TestRun_TickerFires: a short-interval runner observes multiple prune
// calls across a brief window.
func TestRun_TickerFires(t *testing.T) {
	f := &fakeStore{}
	r := NewRunner(f, 20*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()

	waitForCalls(f, 3, 500*time.Millisecond) // 1 startup + 2 ticks
	got := f.callCount()
	cancel()
	<-done
	if got < 3 {
		t.Errorf("prune calls = %d, want >= 3 (1 startup + >= 2 ticks)", got)
	}
}

// TestRun_ZeroInterval_StartupOnly confirms interval <= 0 runs a single
// startup prune and returns without starting the ticker.
func TestRun_ZeroInterval_StartupOnly(t *testing.T) {
	f := &fakeStore{}
	r := NewRunner(f, 0)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		cancel()
		<-done
		t.Fatal("Run did not return with interval=0")
	}
	if f.callCount() != 1 {
		t.Errorf("calls = %d, want exactly 1 (startup prune only)", f.callCount())
	}
}

// TestRun_ContextCancellation_StopsRunner confirms ctx.Done() halts the
// ticker loop.
func TestRun_ContextCancellation_StopsRunner(t *testing.T) {
	f := &fakeStore{}
	r := NewRunner(f, time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()

	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Run did not honour ctx cancellation")
	}
}
