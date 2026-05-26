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

func TestNew_DisabledReturnsNoop(t *testing.T) {
	cfg := config.IntakeDedupConfig{
		Enabled:    false,
		TTLSeconds: 3600,
		MaxEntries: 1000,
	}
	c := New(cfg, time.Hour)
	if _, ok := c.(*Noop); !ok {
		t.Errorf("disabled config returned %T, want *Noop", c)
	}
}

func TestNew_EnabledReturnsLRU(t *testing.T) {
	cfg := config.IntakeDedupConfig{
		Enabled:    true,
		TTLSeconds: 3600,
		MaxEntries: 1000,
	}
	c := New(cfg, 24*time.Hour)
	if _, ok := c.(*LRUCache); !ok {
		t.Errorf("enabled config returned %T, want *LRUCache", c)
	}
}

func TestNew_AppliesTTLSafetyCap(t *testing.T) {
	// Smoke test: factory runs without panic on a configuration where
	// TTL would exceed half the attrition threshold. Underlying cap
	// behaviour is verified in attrition_test.go::TestCapTTL.
	cfg := config.IntakeDedupConfig{
		Enabled:    true,
		TTLSeconds: int((6 * time.Hour) / time.Second),
		MaxEntries: 1000,
	}
	c := New(cfg, 4*time.Hour)
	if c == nil {
		t.Fatal("New returned nil")
	}
	c.Mark("k")
	if !c.Seen("k") {
		t.Error("cache did not record mark")
	}
}
