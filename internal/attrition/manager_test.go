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

package attrition

import (
	"context"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/store"
)

type mockCryptoStore struct {
	store.CryptoStore
	sweepCount int
	lastConfig store.AttritionConfig
}

func (m *mockCryptoStore) MarkStaleAssets(ctx context.Context, cfg store.AttritionConfig) (*store.AttritionSummary, error) {
	m.sweepCount++
	m.lastConfig = cfg
	return &store.AttritionSummary{ByAssetType: map[string]int{}}, nil
}

func TestManagerRunsImmediateSweep(t *testing.T) {
	mock := &mockCryptoStore{}
	cfg := store.AttritionConfig{
		CycleStaleThreshold: 3,
		CycleBasedSources:   []string{"osquery"},
	}

	mgr := NewManager(mock, cfg, 1*time.Hour)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	mgr.Run(ctx)

	if mock.sweepCount < 1 {
		t.Errorf("expected at least 1 sweep, got %d", mock.sweepCount)
	}
	if mock.lastConfig.CycleStaleThreshold != 3 {
		t.Errorf("config not passed correctly: threshold = %d", mock.lastConfig.CycleStaleThreshold)
	}
}
