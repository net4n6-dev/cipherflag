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

// Repository is a Git repository registered for crypto scanning (Layer 6.1).
// Provenance of individual findings lives in asset_health_reports.findings
// JSONB (asset_type='repository', asset_id=id.String()).
type Repository struct {
	ID              string            `json:"id"`
	ProviderID      string            `json:"provider_id"`
	URL             string            `json:"url"`
	DefaultBranch   string            `json:"default_branch"`
	ScheduleCron    string            `json:"schedule_cron,omitempty"`
	DefaultScanMode string            `json:"default_scan_mode"`
	Tags            map[string]string `json:"tags,omitempty"`
	AuthSecretRef   string            `json:"auth_secret_ref,omitempty"`
	LastScannedSHA  string            `json:"last_scanned_sha,omitempty"`
	LastScanAt      *time.Time        `json:"last_scan_at,omitempty"`
	LastScheduledAt *time.Time        `json:"last_scheduled_at,omitempty"`
	FirstSeen       time.Time         `json:"first_seen"`
	LastSeen        time.Time         `json:"last_seen"`
}
