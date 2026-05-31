// Copyright 2026 net4n6-dev
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package sentinelone

import (
	"testing"
	"time"
)

func TestRSOCursor_RoundTripJSON(t *testing.T) {
	now := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	orig := &RSOCursor{
		ActiveTasks: []RSOActiveTask{
			{ScriptID: "s1", TaskID: "t1", LaunchedAt: now},
		},
		LastLaunchAt: now,
	}
	raw, err := orig.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := UnmarshalRSOCursor(raw)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(got.ActiveTasks) != 1 || got.ActiveTasks[0].TaskID != "t1" {
		t.Errorf("active = %+v", got.ActiveTasks)
	}
	if !got.LastLaunchAt.Equal(now) {
		t.Errorf("LastLaunchAt = %v, want %v", got.LastLaunchAt, now)
	}
}

func TestUnmarshalRSOCursor_Empty(t *testing.T) {
	got, err := UnmarshalRSOCursor("")
	if err != nil {
		t.Fatalf("UnmarshalRSOCursor(\"\"): %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil cursor")
	}
	if len(got.ActiveTasks) != 0 {
		t.Errorf("ActiveTasks = %+v", got.ActiveTasks)
	}
}

func TestRSOCursor_Remove(t *testing.T) {
	c := &RSOCursor{
		ActiveTasks: []RSOActiveTask{
			{TaskID: "a"}, {TaskID: "b"}, {TaskID: "c"},
		},
	}
	c.Remove("b")
	if len(c.ActiveTasks) != 2 {
		t.Fatalf("after Remove: %+v", c.ActiveTasks)
	}
	if c.ActiveTasks[0].TaskID != "a" || c.ActiveTasks[1].TaskID != "c" {
		t.Errorf("order = %+v", c.ActiveTasks)
	}
}
