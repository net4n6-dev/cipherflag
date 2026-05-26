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

package scoring

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/store"
)

type sweepFakeStore struct {
	store.CryptoStore
	stale       []store.StaleAssetRow
	unscored    []store.StaleAssetRow
	staleErr    error
	unscoredErr error

	staleCall    int32
	unscoredCall int32
}

func (f *sweepFakeStore) ListStaleAssetHealthRows(_ context.Context, _, _ int) ([]store.StaleAssetRow, error) {
	atomic.AddInt32(&f.staleCall, 1)
	if f.staleErr != nil {
		return nil, f.staleErr
	}
	out := f.stale
	f.stale = nil
	return out, nil
}

func (f *sweepFakeStore) ListUnscoredAssets(_ context.Context, _ int) ([]store.StaleAssetRow, error) {
	atomic.AddInt32(&f.unscoredCall, 1)
	if f.unscoredErr != nil {
		return nil, f.unscoredErr
	}
	out := f.unscored
	f.unscored = nil
	return out, nil
}

type countingScorer struct {
	calls int32
}

func (c *countingScorer) ScoreAsset(context.Context, string, string) error {
	atomic.AddInt32(&c.calls, 1)
	return nil
}

func TestSweeper_RescoresStaleRows(t *testing.T) {
	fs := &sweepFakeStore{
		stale: []store.StaleAssetRow{
			{AssetType: "ssh_key", AssetID: "a"},
			{AssetType: "crypto_library", AssetID: "b"},
		},
	}
	cs := &countingScorer{}
	sw := NewSweeper(fs, cs, time.Hour, 100)
	sw.runOnce(context.Background())

	if cs.calls != 2 {
		t.Errorf("scorer called %d times; want 2", cs.calls)
	}
}

func TestSweeper_ScoresUnscoredAssets(t *testing.T) {
	fs := &sweepFakeStore{
		unscored: []store.StaleAssetRow{
			{AssetType: "certificate", AssetID: "fp-1"},
		},
	}
	cs := &countingScorer{}
	sw := NewSweeper(fs, cs, time.Hour, 100)
	sw.runOnce(context.Background())

	if cs.calls != 1 {
		t.Errorf("scorer called %d times; want 1", cs.calls)
	}
}

func TestSweeper_ContextCancelAborts(t *testing.T) {
	fs := &sweepFakeStore{
		stale: []store.StaleAssetRow{
			{AssetType: "ssh_key", AssetID: "a"},
			{AssetType: "ssh_key", AssetID: "b"},
			{AssetType: "ssh_key", AssetID: "c"},
		},
	}
	cs := &countingScorer{}
	sw := NewSweeper(fs, cs, time.Hour, 100)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sw.runOnce(ctx)

	if cs.calls > 1 {
		t.Errorf("scorer called %d times under cancelled ctx; expected <= 1", cs.calls)
	}
}

func TestSweeper_StaleErrorDoesNotAbortUnscored(t *testing.T) {
	fs := &sweepFakeStore{
		staleErr: errors.New("stale failed"),
		unscored: []store.StaleAssetRow{{AssetType: "ssh_key", AssetID: "a"}},
	}
	cs := &countingScorer{}
	sw := NewSweeper(fs, cs, time.Hour, 100)
	sw.runOnce(context.Background())

	if cs.calls != 1 {
		t.Errorf("scorer called %d times; want 1 (unscored should run after stale error)", cs.calls)
	}
}

func TestSweeper_DefaultsAppliedForZeroValues(t *testing.T) {
	sw := NewSweeper(&sweepFakeStore{}, &countingScorer{}, 0, 0)
	// Construction should not panic; internal defaults apply.
	if sw == nil {
		t.Fatal("NewSweeper returned nil")
	}
}
