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

// AssetProvenance tracks where and how a cryptographic asset was discovered.
type AssetProvenance struct {
	ID        string `json:"id"`
	AssetType string `json:"asset_type"`
	AssetID   string `json:"asset_id"`
	Source    string `json:"source"`
	// ExternalSourceID links this provenance row to an entry in the
	// external_sources registry (v1.10 AWS / future CT / future kinds).
	// Empty string means the FK column stores SQL NULL — file scans
	// and local-agent discoveries don't carry a registry reference.
	// See internal/store/migrations/032_asset_provenance_external_source.sql.
	ExternalSourceID string         `json:"external_source_id,omitempty"`
	HostID           string         `json:"host_id,omitempty"`
	FilePath         string         `json:"file_path,omitempty"`
	StoreType        string         `json:"store_type,omitempty"`
	RawMetadata      map[string]any `json:"raw_metadata,omitempty"`
	FirstSeen        time.Time      `json:"first_seen"`
	LastSeen         time.Time      `json:"last_seen"`
}
