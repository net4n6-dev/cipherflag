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

// ProtocolEndpoint is the scorable asset for Layer 4.1c. It aggregates
// one or more ProtocolObservation rows per (ServerIP, ServerPort, Protocol)
// tuple with worst-ever merge semantics: once a weakness is observed, it
// persists in the endpoint's state until the row is manually reset.
//
// Raw observation history remains in protocol_observations (append-only).
type ProtocolEndpoint struct {
	ID         string `json:"id"`
	HostID     string `json:"host_id,omitempty"`
	ServerIP   string `json:"server_ip"`
	ServerPort int    `json:"server_port"`
	Protocol   string `json:"protocol"` // "TLS" or "SSH"

	// Worst-ever aggregated posture fields (scoring inputs):
	MinTLSVersionSeen   string   `json:"min_tls_version_seen,omitempty"`
	HasSSHv1            bool     `json:"has_sshv1"`
	HasNullExportCipher bool     `json:"has_null_export_cipher"`
	WeakKexSeen         []string `json:"weak_kex_seen,omitempty"`
	WeakCipherSeen      []string `json:"weak_cipher_seen,omitempty"`
	WeakMacSeen         []string `json:"weak_mac_seen,omitempty"`

	// Supplementary detail for reporting (not scoring):
	Details map[string]interface{} `json:"details,omitempty"`

	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}
