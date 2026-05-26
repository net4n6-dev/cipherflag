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

package observcache

import (
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/ingest/dedup"
)

func TestKey_IdenticalObservationsProduceIdenticalHash(t *testing.T) {
	cert := dedup.CertDiscovery{
		FingerprintSHA256: "abc",
		SubjectCN:         "example.com",
		IssuerCN:          "Let's Encrypt R3",
		SerialNumber:      "01",
		NotBefore:         time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:          time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		KeyAlgorithm:      "RSA",
		KeySizeBits:       2048,
		Source:            "sentinelone",
	}
	k1 := Key("sentinelone", "host-1", "certificate", cert)
	k2 := Key("sentinelone", "host-1", "certificate", cert)
	if k1 != k2 {
		t.Errorf("identical observations produced different hashes:\n  %s\n  %s", k1, k2)
	}
}

func TestKey_FieldChangeMutatesHash(t *testing.T) {
	base := dedup.CertDiscovery{FingerprintSHA256: "abc", KeySizeBits: 2048}
	changed := base
	changed.KeySizeBits = 4096

	if Key("s", "h", "certificate", base) == Key("s", "h", "certificate", changed) {
		t.Error("field change did not mutate hash")
	}
}

func TestKey_SourceChangeMutatesHash(t *testing.T) {
	cert := dedup.CertDiscovery{FingerprintSHA256: "abc"}
	if Key("zeek", "h", "certificate", cert) == Key("osquery", "h", "certificate", cert) {
		t.Error("source change did not mutate hash")
	}
}

func TestKey_ResolvedHostChangeMutatesHash(t *testing.T) {
	cert := dedup.CertDiscovery{FingerprintSHA256: "abc"}
	if Key("s", "host-A", "certificate", cert) == Key("s", "host-B", "certificate", cert) {
		t.Error("resolved host change did not mutate hash")
	}
}

func TestKey_AssetTypeChangeMutatesHash(t *testing.T) {
	cert := dedup.CertDiscovery{FingerprintSHA256: "abc"}
	if Key("s", "h", "certificate", cert) == Key("s", "h", "ssh_key", cert) {
		t.Error("asset type change did not mutate hash")
	}
}

func TestKey_MapFieldOrderIndependent(t *testing.T) {
	cfg1 := dedup.ConfigDiscovery{
		ConfigType: "sshd",
		FilePath:   "/etc/ssh/sshd_config",
		Settings: map[string]string{
			"PasswordAuthentication": "no",
			"PermitRootLogin":        "prohibit-password",
		},
	}
	cfg2 := dedup.ConfigDiscovery{
		ConfigType: "sshd",
		FilePath:   "/etc/ssh/sshd_config",
		Settings: map[string]string{
			"PermitRootLogin":        "prohibit-password",
			"PasswordAuthentication": "no",
		},
	}
	if Key("s", "h", "crypto_config", cfg1) != Key("s", "h", "crypto_config", cfg2) {
		t.Error("map fields in different insertion orders produced different hashes")
	}
}

func TestKey_TimestampPrecisionStable(t *testing.T) {
	t1 := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	cert1 := dedup.CertDiscovery{FingerprintSHA256: "abc", NotBefore: t1}
	cert2 := dedup.CertDiscovery{FingerprintSHA256: "abc", NotBefore: t2}
	if Key("s", "h", "certificate", cert1) != Key("s", "h", "certificate", cert2) {
		t.Error("equal timestamps produced different hashes")
	}
}

func TestKey_ReturnsHexSha256(t *testing.T) {
	k := Key("s", "h", "certificate", dedup.CertDiscovery{FingerprintSHA256: "abc"})
	if len(k) != 64 {
		t.Errorf("key length = %d, want 64 (hex sha256)", len(k))
	}
	for _, r := range k {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			t.Errorf("key contains non-hex char: %c", r)
			return
		}
	}
}
