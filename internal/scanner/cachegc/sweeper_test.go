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

package cachegc

import (
	"context"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

type fakeStore struct {
	calls       int
	lastArgs    [4]any
	deletedResp int
}

func (f *fakeStore) SweepCache(ctx context.Context, assetType, rv, pch string, older time.Time) (int, error) {
	f.calls++
	f.lastArgs = [4]any{assetType, rv, pch, older}
	return f.deletedResp, nil
}

func TestSweeper_RunOnce_PassesCurrentVersionsAndCutoff(t *testing.T) {
	f := &fakeStore{deletedResp: 7}
	s := &Sweeper{Store: f, RuleVersion: "v2", PromptContentHash: "", Age: 30 * 24 * time.Hour, Now: func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }}
	n, err := s.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("%v", err)
	}
	if n != 7 {
		t.Errorf("want 7 deleted, got %d", n)
	}
	if f.calls != 1 {
		t.Errorf("calls: %d", f.calls)
	}
	if at, _ := f.lastArgs[0].(string); at != model.AssetTypeRepository {
		t.Errorf("asset_type arg: %q, want %q", at, model.AssetTypeRepository)
	}
	if rv, _ := f.lastArgs[1].(string); rv != "v2" {
		t.Errorf("rule_version arg: %q", rv)
	}
	olderThan, _ := f.lastArgs[3].(time.Time)
	want := time.Unix(1_700_000_000, 0).UTC().Add(-30 * 24 * time.Hour)
	if !olderThan.Equal(want) {
		t.Errorf("cutoff: got %v, want %v", olderThan, want)
	}
}
