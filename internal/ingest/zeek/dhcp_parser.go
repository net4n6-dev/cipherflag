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

// DHCPRecord is one parsed Zeek dhcp.log entry. Zeek aggregates a DHCP
// transaction (DISCOVER / OFFER / REQUEST / ACK across 2–4 packets)
// into a single log row, so one record represents a full lease event.
//
// The identity fields (`mac`, `host_name`, `client_fqdn`, `domain`)
// are populated from DHCP options 12 (host name), 15 (domain name),
// and 81 (client fqdn) when the client sent them. Absent when the
// client opts out — enterprise Windows-joined hosts typically set
// option 81; consumer devices typically don't.
//
// Spec: research/hip-sightings-spec-v1.5.0.md §2 (Zeek corpus) + §4
// (ingest path). Zeek source at scripts/base/protocols/dhcp/main.zeek.
type DHCPRecord struct {
	Timestamp     time.Time
	MAC           string
	HostName      string        // DHCP option 12
	ClientFQDN    string        // DHCP option 81
	Domain        string        // DHCP option 15
	AssignedAddr  string
	RequestedAddr string
	LeaseTime     time.Duration
	MsgTypes      []string      // e.g. ["DISCOVER","OFFER","REQUEST","ACK"]
	ClientAddr    string
	ServerAddr    string
}

// rawDHCP matches Zeek's dhcp.log JSON emission. Optional fields arrive
// as `null` when absent — use pointers so we can distinguish absent
// from empty-string. `lease_time` is serialised as seconds (float).
type rawDHCP struct {
	Ts            float64  `json:"ts"`
	Mac           *string  `json:"mac"`
	HostName      *string  `json:"host_name"`
	ClientFQDN    *string  `json:"client_fqdn"`
	Domain        *string  `json:"domain"`
	AssignedAddr  *string  `json:"assigned_addr"`
	RequestedAddr *string  `json:"requested_addr"`
	LeaseTime     *float64 `json:"lease_time"`
	MsgTypes      []string `json:"msg_types"`
	ClientAddr    *string  `json:"client_addr"`
	ServerAddr    *string  `json:"server_addr"`
}

// ParseDHCPRecord parses a single Zeek dhcp.log JSON line. Missing
// optional fields yield empty strings / zero durations in the record —
// callers check HostName / ClientFQDN / AssignedAddr before using.
func ParseDHCPRecord(data []byte) (*DHCPRecord, error) {
	var raw rawDHCP
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	rec := &DHCPRecord{
		Timestamp: unixToTime(raw.Ts),
		MsgTypes:  raw.MsgTypes,
	}
	if raw.Mac != nil {
		rec.MAC = *raw.Mac
	}
	if raw.HostName != nil {
		rec.HostName = *raw.HostName
	}
	if raw.ClientFQDN != nil {
		rec.ClientFQDN = *raw.ClientFQDN
	}
	if raw.Domain != nil {
		rec.Domain = *raw.Domain
	}
	if raw.AssignedAddr != nil {
		rec.AssignedAddr = *raw.AssignedAddr
	}
	if raw.RequestedAddr != nil {
		rec.RequestedAddr = *raw.RequestedAddr
	}
	if raw.LeaseTime != nil && *raw.LeaseTime > 0 {
		rec.LeaseTime = time.Duration(*raw.LeaseTime) * time.Second
	}
	if raw.ClientAddr != nil {
		rec.ClientAddr = *raw.ClientAddr
	}
	if raw.ServerAddr != nil {
		rec.ServerAddr = *raw.ServerAddr
	}
	return rec, nil
}
