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
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestLRU_FirstSeenIsMiss_SecondIsHit(t *testing.T) {
	c := NewLRU(100, time.Hour)
	if c.Seen("k") {
		t.Fatal("first Seen should be miss")
	}
	c.Mark("k")
	if !c.Seen("k") {
		t.Fatal("Seen after Mark should be hit")
	}
}

func TestLRU_TTLExpiry(t *testing.T) {
	c := NewLRU(100, 50*time.Millisecond)
	c.Mark("k")
	if !c.Seen("k") {
		t.Fatal("Seen immediately after Mark should be hit")
	}
	time.Sleep(100 * time.Millisecond)
	if c.Seen("k") {
		t.Error("Seen after TTL should be miss")
	}
}

func TestLRU_LRUEvictionUnderSizePressure(t *testing.T) {
	c := NewLRU(3, time.Hour)
	c.Mark("a")
	c.Mark("b")
	c.Mark("c")
	if c.Size() != 3 {
		t.Fatalf("Size = %d, want 3", c.Size())
	}
	c.Mark("d") // should evict "a" (oldest)
	if c.Seen("a") {
		t.Error("oldest entry 'a' should have been evicted")
	}
	if !c.Seen("d") {
		t.Error("newest entry 'd' should be present")
	}
	if c.Size() != 3 {
		t.Errorf("Size after eviction = %d, want 3", c.Size())
	}
}

func TestLRU_SeenAndMark_ReflectsState(t *testing.T) {
	c := NewLRU(10, time.Hour)
	if c.SeenAndMark("k") {
		t.Fatal("SeenAndMark first call should return false")
	}
	if !c.SeenAndMark("k") {
		t.Fatal("SeenAndMark second call should return true")
	}
}

func TestLRU_ConcurrentAccess_RaceSafe(t *testing.T) {
	c := NewLRU(1000, time.Hour)
	var wg sync.WaitGroup
	for g := 0; g < 50; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				k := fmt.Sprintf("g%d-%d", id, i)
				c.Mark(k)
				c.Seen(k)
				c.SeenAndMark(k)
			}
		}(g)
	}
	wg.Wait()
}

func TestLRU_NewLRU_ClampsZeroSize(t *testing.T) {
	c := NewLRU(0, time.Hour)
	c.Mark("k")
	// Should not panic; should have clamped internal size to minimum.
	if c.Size() < 0 {
		t.Errorf("Size negative: %d", c.Size())
	}
}

func TestLRU_NewLRU_ClampsZeroTTL(t *testing.T) {
	c := NewLRU(100, 0)
	c.Mark("k")
	// Zero TTL must clamp to a minimum positive duration — otherwise
	// every entry would expire immediately.
	if !c.Seen("k") {
		t.Error("entry expired immediately with zero-ttl clamp failing")
	}
}
