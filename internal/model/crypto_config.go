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

// CryptoConfig represents a cryptographic configuration file on a host.
type CryptoConfig struct {
	ID              string            `json:"id"`
	HostID          string            `json:"host_id"`
	ConfigType      string            `json:"config_type"`
	FilePath        string            `json:"file_path"`
	Settings        map[string]string `json:"settings"`
	Findings        []ConfigIssue     `json:"findings,omitempty"`
	Source          string            `json:"source"`
	DiscoveryStatus string            `json:"discovery_status"`
	FirstSeen       time.Time         `json:"first_seen"`
	LastSeen        time.Time         `json:"last_seen"`
}

// ConfigIssue represents a problem found in a crypto configuration.
type ConfigIssue struct {
	Setting  string `json:"setting"`
	Value    string `json:"value"`
	Issue    string `json:"issue"`
	Severity string `json:"severity"`
}
