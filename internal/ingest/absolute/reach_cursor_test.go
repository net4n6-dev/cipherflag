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

package absolute

import (
	"testing"
	"time"
)

func TestReachCursor_RoundTripJSON(t *testing.T) {
	now := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	orig := &ReachCursor{
		ActiveExecutions: []ReachActiveExecution{
			{ScriptID: "s1", ExecutionID: "e1", LaunchedAt: now},
		},
		LastLaunchAt: now,
	}
	raw, err := orig.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := UnmarshalReachCursor(raw)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(got.ActiveExecutions) != 1 || got.ActiveExecutions[0].ExecutionID != "e1" {
		t.Errorf("active = %+v", got.ActiveExecutions)
	}
	if !got.LastLaunchAt.Equal(now) {
		t.Errorf("LastLaunchAt = %v, want %v", got.LastLaunchAt, now)
	}
}

func TestUnmarshalReachCursor_Empty(t *testing.T) {
	got, err := UnmarshalReachCursor("")
	if err != nil {
		t.Fatalf("UnmarshalReachCursor(\"\"): %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil cursor")
	}
	if len(got.ActiveExecutions) != 0 {
		t.Errorf("ActiveExecutions = %+v", got.ActiveExecutions)
	}
}

func TestReachCursor_Remove(t *testing.T) {
	c := &ReachCursor{
		ActiveExecutions: []ReachActiveExecution{
			{ExecutionID: "a"}, {ExecutionID: "b"}, {ExecutionID: "c"},
		},
	}
	c.Remove("b")
	if len(c.ActiveExecutions) != 2 {
		t.Fatalf("after Remove: %+v", c.ActiveExecutions)
	}
	if c.ActiveExecutions[0].ExecutionID != "a" || c.ActiveExecutions[1].ExecutionID != "c" {
		t.Errorf("order = %+v", c.ActiveExecutions)
	}
}
