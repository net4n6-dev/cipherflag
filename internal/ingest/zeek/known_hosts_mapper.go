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
	"time"

	"github.com/net4n6-dev/cipherflag/internal/store"
)

// KnownHostsDailyWindow is the time window we write around each
// known_hosts.log row. Zeek's known-hosts script emits one row per
// (IP, day) at `create_expire=1day` — the row literally means "the IP
// was observed active at least once during that 24-hour bucket". We
// round up to a 24h window so the point-in-time lookup for any cert
// observation that shares the same day resolves.
const KnownHostsDailyWindow = 24 * time.Hour

// MapKnownHostsToSighting converts a parsed known_hosts.log row into a
// host_ip_sighting with:
//
//   - source='zeek_known_hosts'
//   - confidence='observed'  (IP was live; no identity)
//   - host_id NULL           (known_hosts does not attribute to a host)
//   - window=[ts, ts+24h]    (Zeek's daily bucket semantics)
//   - attribution={}         (no extras — confidence is self-contained)
//
// Spec: research/hip-sightings-spec-v1.5.0.md §4, §5 attribution table.
func MapKnownHostsToSighting(rec *KnownHostsRecord) *store.HostIPSighting {
	return &store.HostIPSighting{
		IP:         rec.Host,
		FirstSeen:  rec.Timestamp,
		LastSeen:   rec.Timestamp.Add(KnownHostsDailyWindow),
		Source:     "zeek_known_hosts",
		Confidence: "observed",
		// HostID intentionally empty — confidence=observed means we
		// saw the IP live, not whose it is. Cert blast-radius filters
		// NULL host_id out of the attributed path and routes these
		// rows to the unattributed aggregate.
	}
}
