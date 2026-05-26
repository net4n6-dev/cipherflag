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
	"time"

	"github.com/net4n6-dev/cipherflag/internal/config"
)

// HardFloor is the absolute minimum attrition threshold the helper will
// return when the config is entirely unconfigured. Ensures even a
// pathological config can't bypass TTL capping.
const HardFloor = time.Hour

// ShortestAttritionThreshold computes the minimum across the configured
// attrition fields, converted to a common duration.
//
// Inputs:
//   - cfg: the AttritionConfig from internal/config
//   - shortestPollInterval: the smallest poll interval across enabled
//     endpoint sources, used to convert cycle-based thresholds to
//     duration. Zero or negative means "no endpoint source enabled" —
//     cycle thresholds are skipped.
//
// Zero-valued thresholds are treated as absent and skipped.
//
// If every threshold is absent or zero, returns HardFloor.
func ShortestAttritionThreshold(cfg config.AttritionConfig, shortestPollInterval time.Duration) time.Duration {
	candidates := []time.Duration{}

	if cfg.NetworkStaleDays > 0 {
		candidates = append(candidates, time.Duration(cfg.NetworkStaleDays)*24*time.Hour)
	}
	if cfg.NetworkRemovedDays > 0 {
		candidates = append(candidates, time.Duration(cfg.NetworkRemovedDays)*24*time.Hour)
	}
	if shortestPollInterval > 0 {
		if cfg.CycleStaleThreshold > 0 {
			candidates = append(candidates, time.Duration(cfg.CycleStaleThreshold)*shortestPollInterval)
		}
		if cfg.CycleRemovedThreshold > 0 {
			candidates = append(candidates, time.Duration(cfg.CycleRemovedThreshold)*shortestPollInterval)
		}
	}

	if len(candidates) == 0 {
		return HardFloor
	}

	min := candidates[0]
	for _, d := range candidates[1:] {
		if d < min {
			min = d
		}
	}
	return min
}

// CapTTL returns the smaller of ttl and threshold/2. Guarantees the
// configured TTL can never exceed half the shortest attrition threshold.
func CapTTL(ttl, threshold time.Duration) time.Duration {
	cap := threshold / 2
	if ttl > cap {
		return cap
	}
	return ttl
}
