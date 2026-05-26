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

package observcache

import (
	"sync"
	"testing"
)

func TestMetrics_RecordsHitsAndMisses(t *testing.T) {
	m := NewMetrics()
	m.RecordHit("sentinelone", "certificate")
	m.RecordHit("sentinelone", "certificate")
	m.RecordMiss("sentinelone", "certificate")
	m.RecordMiss("tanium", "library")

	snap := m.Snapshot()
	if snap.TotalHits != 2 {
		t.Errorf("TotalHits = %d, want 2", snap.TotalHits)
	}
	if snap.TotalMisses != 2 {
		t.Errorf("TotalMisses = %d, want 2", snap.TotalMisses)
	}
	key := SourceAssetKey{Source: "sentinelone", AssetType: "certificate"}
	if got := snap.PerSourceAssetHits[key]; got != 2 {
		t.Errorf("PerSourceAssetHits[sentinelone/certificate] = %d, want 2", got)
	}
}

func TestMetrics_HitRate(t *testing.T) {
	m := NewMetrics()
	for i := 0; i < 97; i++ {
		m.RecordHit("s", "a")
	}
	for i := 0; i < 3; i++ {
		m.RecordMiss("s", "a")
	}
	snap := m.Snapshot()
	if snap.HitRate < 0.96 || snap.HitRate > 0.98 {
		t.Errorf("HitRate = %f, want ~0.97", snap.HitRate)
	}
}

func TestMetrics_HitRate_ZeroDivisionSafe(t *testing.T) {
	m := NewMetrics()
	snap := m.Snapshot()
	if snap.HitRate != 0 {
		t.Errorf("HitRate on empty metrics = %f, want 0", snap.HitRate)
	}
}

func TestMetrics_ConcurrentAccess_RaceSafe(t *testing.T) {
	m := NewMetrics()
	var wg sync.WaitGroup
	for g := 0; g < 20; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				m.RecordHit("s", "a")
				m.RecordMiss("s", "b")
			}
		}()
	}
	wg.Wait()
	snap := m.Snapshot()
	if snap.TotalHits != 20*500 {
		t.Errorf("TotalHits = %d, want %d", snap.TotalHits, 20*500)
	}
}

func TestMetrics_ResetClearsCounters(t *testing.T) {
	m := NewMetrics()
	m.RecordHit("s", "a")
	m.RecordMiss("s", "a")
	m.Reset()
	snap := m.Snapshot()
	if snap.TotalHits != 0 || snap.TotalMisses != 0 {
		t.Errorf("after Reset: hits=%d misses=%d, want 0/0", snap.TotalHits, snap.TotalMisses)
	}
}
