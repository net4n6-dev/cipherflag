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
	"encoding/json"
	"time"
)

// ReachActiveExecution represents one in-flight Reach execution.
type ReachActiveExecution struct {
	ScriptID    string    `json:"script_id"`
	ExecutionID string    `json:"execution_id"`
	LaunchedAt  time.Time `json:"launched_at"`
}

// ReachCursor is serialised to ingestion_state.cursor for the
// SourceNameReach key. Persisting execution state across cycles lets
// long-running Reach executions survive process restarts.
type ReachCursor struct {
	ActiveExecutions []ReachActiveExecution `json:"active_executions"`
	LastLaunchAt     time.Time              `json:"last_launch_at"`
}

// Marshal encodes the cursor as JSON for storage.
func (c *ReachCursor) Marshal() (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// UnmarshalReachCursor decodes a stored cursor string. An empty string
// yields a zero-valued cursor.
func UnmarshalReachCursor(raw string) (*ReachCursor, error) {
	c := &ReachCursor{}
	if raw == "" {
		return c, nil
	}
	if err := json.Unmarshal([]byte(raw), c); err != nil {
		return nil, err
	}
	return c, nil
}

// Remove drops the execution with the given ID from ActiveExecutions,
// preserving order of remaining entries.
func (c *ReachCursor) Remove(executionID string) {
	out := c.ActiveExecutions[:0]
	for _, e := range c.ActiveExecutions {
		if e.ExecutionID != executionID {
			out = append(out, e)
		}
	}
	c.ActiveExecutions = out
}
