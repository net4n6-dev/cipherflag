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

type EndpointProfile struct {
	ServerIP              string     `json:"server_ip"`
	ServerPort            int        `json:"server_port"`
	ServerName            string     `json:"server_name,omitempty"`
	CertFingerprint       string     `json:"cert_fingerprint"`
	MinTLSVersion         TLSVersion `json:"min_tls_version"`
	MaxTLSVersion         TLSVersion `json:"max_tls_version"`
	CipherSuites          []string   `json:"cipher_suites"`
	SupportsForwardSecrecy bool      `json:"supports_forward_secrecy"`
	SupportsAEAD          bool       `json:"supports_aead"`
	HasWeakCiphers        bool       `json:"has_weak_ciphers"`
	ObservationCount      int        `json:"observation_count"`
	FirstSeen             time.Time  `json:"first_seen"`
	LastSeen              time.Time  `json:"last_seen"`
}
