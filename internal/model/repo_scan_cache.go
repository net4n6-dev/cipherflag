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

// Asset type discriminators for repo_scan_cache (migration 016 / Layer 6.2a).
// Prevents blob-SHA collisions between git blob caches (6.1) and container
// image layer/file caches (6.2) — the same bytes can exist in both worlds
// and must be cached independently per asset_type.
const (
	AssetTypeRepository     = "repository"
	AssetTypeContainerImage = "container_image"
)

// RepoScanCacheEntry caches the result of scanning a single blob under a
// specific (rule_version, prompt_content_hash, scan_mode, asset_type) tuple.
// Cache hits skip detection entirely. Eviction: LRU by scanned_at when a
// configured max_rows is exceeded; purge of orphans older than 30 days is a
// background sweeper concern deferred to 6.1b-4.
type RepoScanCacheEntry struct {
	BlobSHA           []byte    `json:"blob_sha"` // raw 32-byte SHA-256
	RuleVersion       string    `json:"rule_version"`
	PromptContentHash string    `json:"prompt_content_hash"` // '' for deterministic_only
	ScanMode          string    `json:"scan_mode"`
	AssetType         string    `json:"asset_type"`    // "repository" | "container_image"
	FindingsJSON      []byte    `json:"findings_json"` // raw JSONB bytes; unmarshal at call site
	ScannedAt         time.Time `json:"scanned_at"`
	TokenCost         int       `json:"token_cost"`
}
