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
	"encoding/json"
	"time"
)

// RSOActiveTask represents one in-flight RSO execution.
type RSOActiveTask struct {
	ScriptID   string    `json:"script_id"`
	TaskID     string    `json:"task_id"`
	LaunchedAt time.Time `json:"launched_at"`
}

// RSOCursor is serialised to ingestion_state.cursor for the
// SourceNameRSO key. Persisting task state across cycles lets long-running
// executions survive process restarts.
type RSOCursor struct {
	ActiveTasks  []RSOActiveTask `json:"active_tasks"`
	LastLaunchAt time.Time       `json:"last_launch_at"`
}

// Marshal encodes the cursor as JSON for storage.
func (c *RSOCursor) Marshal() (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// UnmarshalRSOCursor decodes a stored cursor string. An empty string yields
// a zero-valued cursor (no active tasks, zero LastLaunchAt).
func UnmarshalRSOCursor(raw string) (*RSOCursor, error) {
	c := &RSOCursor{}
	if raw == "" {
		return c, nil
	}
	if err := json.Unmarshal([]byte(raw), c); err != nil {
		return nil, err
	}
	return c, nil
}

// Remove drops the task with the given ID from ActiveTasks (preserving
// order of remaining entries).
func (c *RSOCursor) Remove(taskID string) {
	out := c.ActiveTasks[:0]
	for _, t := range c.ActiveTasks {
		if t.TaskID != taskID {
			out = append(out, t)
		}
	}
	c.ActiveTasks = out
}
