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

package model

import "time"

type SourceHealth struct {
	Name            string    `json:"name"`
	Type            string    `json:"type"` // "zeek_file", "corelight", "active_scan"
	Status          string    `json:"status"` // "running", "stopped", "error"
	CertsDiscovered int       `json:"certs_discovered"`
	ObservationsTotal int     `json:"observations_total"`
	LastRun         time.Time `json:"last_run"`
	LastError       string    `json:"last_error,omitempty"`
}

type IngestionState struct {
	SourceName string    `json:"source_name"`
	Cursor     string    `json:"cursor"` // File offset, API cursor, etc.
	UpdatedAt  time.Time `json:"updated_at"`
}

type PCAPJob struct {
	ID          string     `json:"id"`
	Filename    string     `json:"filename"`
	FileSize    int64      `json:"file_size"`
	Status      string     `json:"status"`
	CertsFound  int        `json:"certs_found"`
	CertsNew    int        `json:"certs_new"`
	Error       string     `json:"error,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}
