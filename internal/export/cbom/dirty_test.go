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

package cbom

import (
	"sync"
	"testing"
)

func TestDirtySet_MarkAndDrain(t *testing.T) {
	ds := newDirtySet()
	ds.Mark("scope-a")
	ds.Mark("scope-b")
	ds.Mark("scope-a") // duplicate

	names := ds.Drain()
	if len(names) != 2 {
		t.Fatalf("expected 2 unique names, got %d: %v", len(names), names)
	}

	// Drain again — should be empty
	second := ds.Drain()
	if second != nil {
		t.Errorf("expected nil after drain, got %v", second)
	}
}

func TestDirtySet_EmptyDrain(t *testing.T) {
	ds := newDirtySet()
	names := ds.Drain()
	if names != nil {
		t.Errorf("expected nil for empty drain, got %v", names)
	}
}

func TestDirtySet_ConcurrentMark(t *testing.T) {
	ds := newDirtySet()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			ds.Mark("scope")
		}(i)
	}
	wg.Wait()
	names := ds.Drain()
	if len(names) != 1 {
		t.Errorf("expected 1 unique name after concurrent marks, got %d", len(names))
	}
}
