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
)

func TestNoop_SeenAlwaysReturnsFalse(t *testing.T) {
	c := NewNoop()
	if c.Seen("any-key") {
		t.Error("Noop.Seen returned true; expected false")
	}
	c.Mark("any-key")
	if c.Seen("any-key") {
		t.Error("Noop.Seen returned true after Mark; expected false")
	}
}

func TestNoop_SeenAndMarkAlwaysReturnsFalse(t *testing.T) {
	c := NewNoop()
	if c.SeenAndMark("x") {
		t.Error("Noop.SeenAndMark returned true on first call")
	}
	if c.SeenAndMark("x") {
		t.Error("Noop.SeenAndMark returned true on repeat call")
	}
}

func TestNoop_SizeAlwaysZero(t *testing.T) {
	c := NewNoop()
	c.Mark("a")
	c.Mark("b")
	c.Mark("c")
	if c.Size() != 0 {
		t.Errorf("Noop.Size = %d, want 0", c.Size())
	}
}
