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

import "testing"

func TestMapSSHToProtocolDiscovery(t *testing.T) {
	rec := &SSHRecord{
		Timestamp:  1712000000.0,
		ServerIP:   "192.168.1.10",
		ServerPort: 22,
		Version:    2,
		Cipher:     "chacha20-poly1305@openssh.com",
		MAC:        "umac-64-etm@openssh.com",
		KexAlg:     "curve25519-sha256",
		HostKeyAlg: "ssh-ed25519",
	}

	disc := MapSSHToProtocolDiscovery(rec)

	if disc.Protocol != "ssh" {
		t.Errorf("Protocol = %q, want ssh", disc.Protocol)
	}
	if disc.Version != "2" {
		t.Errorf("Version = %q, want 2", disc.Version)
	}
	if disc.ServerIP != "192.168.1.10" {
		t.Errorf("ServerIP = %q", disc.ServerIP)
	}
	if disc.ServerPort != 22 {
		t.Errorf("ServerPort = %d", disc.ServerPort)
	}
	if disc.Algorithms["kex"] != "curve25519-sha256" {
		t.Errorf("Algorithms[kex] = %q", disc.Algorithms["kex"])
	}
	if disc.Algorithms["cipher"] != "chacha20-poly1305@openssh.com" {
		t.Errorf("Algorithms[cipher] = %q", disc.Algorithms["cipher"])
	}
	if disc.Algorithms["mac"] != "umac-64-etm@openssh.com" {
		t.Errorf("Algorithms[mac] = %q", disc.Algorithms["mac"])
	}
	if disc.Algorithms["host_key"] != "ssh-ed25519" {
		t.Errorf("Algorithms[host_key] = %q", disc.Algorithms["host_key"])
	}
	if disc.IsQuantumSafe {
		t.Error("expected IsQuantumSafe = false for current SSH algorithms")
	}
	if disc.ObservedAt.IsZero() {
		t.Error("expected non-zero ObservedAt")
	}
}

func TestMapSSHToProtocolDiscovery_SSHv1(t *testing.T) {
	rec := &SSHRecord{
		Timestamp:  1712000001.0,
		ServerIP:   "192.168.1.11",
		ServerPort: 22,
		Version:    1,
		Cipher:     "3des-cbc",
	}

	disc := MapSSHToProtocolDiscovery(rec)

	if disc.Version != "1" {
		t.Errorf("Version = %q, want 1", disc.Version)
	}
}
