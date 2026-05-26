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

import "sync"

// dirtySet is a thread-safe set of scope names that have pending CBOM emission.
// The drain goroutine empties it on each tick; the notify worker fills it.
type dirtySet struct {
	mu  sync.Mutex
	set map[string]struct{}
}

func newDirtySet() *dirtySet {
	return &dirtySet{set: make(map[string]struct{})}
}

// Mark adds name to the set. Safe to call from multiple goroutines.
func (d *dirtySet) Mark(name string) {
	d.mu.Lock()
	d.set[name] = struct{}{}
	d.mu.Unlock()
}

// Drain removes and returns all names currently in the set.
// Returns nil if the set is empty (avoids allocating a slice).
func (d *dirtySet) Drain() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.set) == 0 {
		return nil
	}
	names := make([]string, 0, len(d.set))
	for n := range d.set {
		names = append(names, n)
	}
	d.set = make(map[string]struct{})
	return names
}
