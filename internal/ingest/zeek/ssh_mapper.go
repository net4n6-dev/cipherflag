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
	"strconv"

	"github.com/net4n6-dev/cipherflag/internal/ingest/dedup"
	"github.com/net4n6-dev/cipherflag/internal/model"
)

// MapSSHToProtocolDiscovery converts a Zeek SSH record to a protocol discovery.
// Algorithms map captures kex, cipher, mac, and host_key fields.
// IsQuantumSafe is hardcoded false — no PQC SSH kex is deployed in practice.
func MapSSHToProtocolDiscovery(rec *SSHRecord) *dedup.ProtocolDiscovery {
	return &dedup.ProtocolDiscovery{
		ServerIP:   rec.ServerIP,
		ServerPort: rec.ServerPort,
		Protocol:   "ssh",
		Version:    strconv.Itoa(rec.Version),
		Algorithms: map[string]string{
			"kex":      rec.KexAlg,
			"cipher":   rec.Cipher,
			"mac":      rec.MAC,
			"host_key": rec.HostKeyAlg,
		},
		IsQuantumSafe: false,
		Source:        string(model.SourceZeekPassive),
		ObservedAt:    unixToTime(rec.Timestamp),
	}
}
