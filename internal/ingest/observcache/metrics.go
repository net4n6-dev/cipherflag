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
)

// SourceAssetKey identifies a (source, asset_type) pair for metric breakdowns.
type SourceAssetKey struct {
	Source    string
	AssetType string
}

// MetricsSnapshot is a point-in-time copy of cache metrics safe for
// logging / serialisation.
type MetricsSnapshot struct {
	TotalHits            int64
	TotalMisses          int64
	HitRate              float64
	PerSourceAssetHits   map[SourceAssetKey]int64
	PerSourceAssetMisses map[SourceAssetKey]int64
}

// Metrics tracks hit/miss counts for the observation cache.
// Thread-safe.
type Metrics struct {
	mu           sync.Mutex
	totalHits    int64
	totalMisses  int64
	perKeyHits   map[SourceAssetKey]int64
	perKeyMisses map[SourceAssetKey]int64
}

// NewMetrics constructs an empty Metrics.
func NewMetrics() *Metrics {
	return &Metrics{
		perKeyHits:   make(map[SourceAssetKey]int64),
		perKeyMisses: make(map[SourceAssetKey]int64),
	}
}

// RecordHit increments the hit count for (source, assetType).
func (m *Metrics) RecordHit(source, assetType string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.totalHits++
	m.perKeyHits[SourceAssetKey{source, assetType}]++
}

// RecordMiss increments the miss count for (source, assetType).
func (m *Metrics) RecordMiss(source, assetType string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.totalMisses++
	m.perKeyMisses[SourceAssetKey{source, assetType}]++
}

// Snapshot returns a stable copy of current counters plus computed hit rate.
func (m *Metrics) Snapshot() MetricsSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()

	total := m.totalHits + m.totalMisses
	hitRate := 0.0
	if total > 0 {
		hitRate = float64(m.totalHits) / float64(total)
	}

	snap := MetricsSnapshot{
		TotalHits:            m.totalHits,
		TotalMisses:          m.totalMisses,
		HitRate:              hitRate,
		PerSourceAssetHits:   make(map[SourceAssetKey]int64, len(m.perKeyHits)),
		PerSourceAssetMisses: make(map[SourceAssetKey]int64, len(m.perKeyMisses)),
	}
	for k, v := range m.perKeyHits {
		snap.PerSourceAssetHits[k] = v
	}
	for k, v := range m.perKeyMisses {
		snap.PerSourceAssetMisses[k] = v
	}
	return snap
}

// Reset clears all counters.
func (m *Metrics) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.totalHits = 0
	m.totalMisses = 0
	m.perKeyHits = make(map[SourceAssetKey]int64)
	m.perKeyMisses = make(map[SourceAssetKey]int64)
}
