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

// SSHKey represents a discovered SSH key on a host.
type SSHKey struct {
	ID                string    `json:"id"`
	HostID            string    `json:"host_id"`
	KeyType           string    `json:"key_type"`
	KeySizeBits       int       `json:"key_size_bits"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	FilePath          string    `json:"file_path,omitempty"`
	OwnerUser         string    `json:"owner_user,omitempty"`
	IsAuthorized      bool      `json:"is_authorized"`
	IsProtected       bool      `json:"is_protected"`
	GrantsRoot        bool      `json:"grants_root"`
	Comment           string    `json:"comment,omitempty"`
	Source            string    `json:"source"`
	DiscoveryStatus   string    `json:"discovery_status"`
	FirstSeen         time.Time `json:"first_seen"`
	LastSeen          time.Time `json:"last_seen"`
}
