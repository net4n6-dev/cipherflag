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

// LineageLink is a directed, typed relationship between two crypto assets
// of any kind. Rows are created by the scanner (Layer 6.1b) during scan
// finalization whenever a repo-discovered cert/SSH-key fingerprint matches
// an existing fingerprint in certificates / ssh_keys.
//
// Note: LinkType is an open string; current values are:
//   - "cert_fingerprint_match"      (from=repository, to=certificate)
//   - "ssh_key_fingerprint_match"   (from=repository, to=ssh_key)
//
// Future layers may add more.
type LineageLink struct {
	ID            string         `json:"id"`
	FromAssetType string         `json:"from_asset_type"`
	FromAssetID   string         `json:"from_asset_id"`
	ToAssetType   string         `json:"to_asset_type"`
	ToAssetID     string         `json:"to_asset_id"`
	LinkType      string         `json:"link_type"`
	Confidence    float64        `json:"confidence"`
	Evidence      map[string]any `json:"evidence,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
}
