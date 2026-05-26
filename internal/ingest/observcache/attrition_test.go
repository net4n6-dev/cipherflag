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
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/config"
)

func TestShortestAttritionThreshold_DefaultConfig(t *testing.T) {
	// Defaults: CycleStaleThreshold=3, CycleRemovedThreshold=7,
	// NetworkStaleDays=7, NetworkRemovedDays=30
	// Shortest poll interval: 1h
	cfg := config.AttritionConfig{
		CycleStaleThreshold:   3,
		CycleRemovedThreshold: 7,
		NetworkStaleDays:      7,
		NetworkRemovedDays:    30,
	}
	got := ShortestAttritionThreshold(cfg, time.Hour)
	// 3 cycles × 1h = 3h; NetworkStaleDays = 7 days. Shortest is 3h.
	want := 3 * time.Hour
	if got != want {
		t.Errorf("ShortestAttritionThreshold = %v, want %v", got, want)
	}
}

func TestShortestAttritionThreshold_ZeroPollIntervalSkipsCycle(t *testing.T) {
	cfg := config.AttritionConfig{
		CycleStaleThreshold:   3,
		CycleRemovedThreshold: 7,
		NetworkStaleDays:      7,
		NetworkRemovedDays:    30,
	}
	// No endpoint sources enabled (zero poll interval) → cycle thresholds
	// are skipped; NetworkStaleDays is the floor.
	got := ShortestAttritionThreshold(cfg, 0)
	want := 7 * 24 * time.Hour
	if got != want {
		t.Errorf("ShortestAttritionThreshold (no cycles) = %v, want %v", got, want)
	}
}

func TestShortestAttritionThreshold_HandlesZeroFields(t *testing.T) {
	// Zero-valued fields should not be treated as "0 duration is smallest" —
	// they should be ignored.
	cfg := config.AttritionConfig{
		CycleStaleThreshold:   0, // absent / disabled
		CycleRemovedThreshold: 0,
		NetworkStaleDays:      7,
		NetworkRemovedDays:    0,
	}
	got := ShortestAttritionThreshold(cfg, time.Hour)
	want := 7 * 24 * time.Hour
	if got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestShortestAttritionThreshold_UnconfiguredReturnsHardFloor(t *testing.T) {
	// Entirely zeroed config — helper returns a conservative hard floor.
	cfg := config.AttritionConfig{}
	got := ShortestAttritionThreshold(cfg, 0)
	// Hard floor: 1 hour. Enough that even a 30m TTL is safe (well below half).
	want := time.Hour
	if got != want {
		t.Errorf("got %v, want %v (hard floor)", got, want)
	}
}

func TestCapTTL_ClampsToHalfShortestThreshold(t *testing.T) {
	// Threshold = 6h. Half = 3h. Configured TTL = 5h → should clamp to 3h.
	got := CapTTL(5*time.Hour, 6*time.Hour)
	want := 3 * time.Hour
	if got != want {
		t.Errorf("CapTTL(5h, 6h) = %v, want %v", got, want)
	}
}

func TestCapTTL_PreservesTTLBelowCap(t *testing.T) {
	// Threshold = 24h. Half = 12h. Configured TTL = 1h → preserved.
	got := CapTTL(time.Hour, 24*time.Hour)
	want := time.Hour
	if got != want {
		t.Errorf("CapTTL(1h, 24h) = %v, want %v", got, want)
	}
}
