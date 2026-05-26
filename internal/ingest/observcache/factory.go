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

// New constructs an ObservationCache from config. Returns a Noop when
// dedup is disabled, or an LRUCache with TTL hard-capped at half the
// shortest attrition threshold.
//
// attritionThreshold is the caller-computed shortest attrition threshold
// (see ShortestAttritionThreshold). Keeping the computation outside the
// factory avoids re-coupling observcache to config details about sources.
func New(cfg config.IntakeDedupConfig, attritionThreshold time.Duration) ObservationCache {
	if !cfg.Enabled {
		return NewNoop()
	}
	configuredTTL := time.Duration(cfg.TTLSeconds) * time.Second
	effectiveTTL := CapTTL(configuredTTL, attritionThreshold)
	return NewLRU(cfg.MaxEntries, effectiveTTL)
}
