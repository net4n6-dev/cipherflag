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

package zeek

import (
	"encoding/json"
	"time"
)

// KnownHostsRecord is one parsed Zeek known_hosts.log entry. The log is
// minimal by design — two fields only. Zeek's policy/protocols/conn/
// known-hosts.zeek logs one row per (IP, day) after a completed TCP
// handshake. LOCAL_HOSTS scope only; spec §2 research corpus.
type KnownHostsRecord struct {
	Timestamp time.Time
	Host      string // IPv4 or IPv6 address observed as active
}

// rawKnownHosts matches Zeek's known_hosts.log JSON emission shape.
// No nested `id.*` compound keys here — Zeek's known_hosts emits flat
// `ts` + `host` only.
type rawKnownHosts struct {
	Ts   float64 `json:"ts"`
	Host string  `json:"host"`
}

// ParseKnownHostsRecord parses a single Zeek known_hosts.log JSON line.
// Spec: research/hip-sightings-spec-v1.5.0.md §2 (Zeek corpus) + §4
// (ingest path). The Zeek script source is at zeek/zeek
// scripts/policy/protocols/conn/known-hosts.zeek.
func ParseKnownHostsRecord(data []byte) (*KnownHostsRecord, error) {
	var raw rawKnownHosts
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	return &KnownHostsRecord{
		Timestamp: unixToTime(raw.Ts),
		Host:      raw.Host,
	}, nil
}
