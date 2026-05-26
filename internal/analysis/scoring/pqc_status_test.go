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

package scoring

import (
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/analysis/pqc"
	"github.com/net4n6-dev/cipherflag/internal/model"
)

func TestForCertificate(t *testing.T) {
	cases := []struct {
		alg  string
		want string
	}{
		{"RSA", string(pqc.QuantumVulnerable)},
		{"ECDSA", string(pqc.QuantumVulnerable)},
		{"Ed25519", string(pqc.QuantumVulnerable)},
		{"ML-KEM-768", string(pqc.QuantumSafe)},
		{"SomeMadeUpAlg", string(pqc.QuantumUnknown)},
	}
	for _, tc := range cases {
		cert := &model.Certificate{KeyAlgorithm: model.KeyAlgorithm(tc.alg)}
		if got := ForCertificate(cert); got != tc.want {
			t.Errorf("ForCertificate(%s) = %s, want %s", tc.alg, got, tc.want)
		}
	}
}

func TestForSSHKey(t *testing.T) {
	cases := []struct {
		keyType string
		want    string
	}{
		{"ssh-rsa", string(pqc.QuantumVulnerable)},
		{"ssh-ed25519", string(pqc.QuantumVulnerable)},
		{"ecdsa-sha2-nistp256", string(pqc.QuantumVulnerable)},
		{"ssh-dss", string(pqc.QuantumVulnerable)},
	}
	for _, tc := range cases {
		k := &model.SSHKey{KeyType: tc.keyType}
		if got := ForSSHKey(k); got != tc.want {
			t.Errorf("ForSSHKey(%s) = %s, want %s", tc.keyType, got, tc.want)
		}
	}
}

func TestForLibrary_PQCCapableIsSafe(t *testing.T) {
	lib := &model.CryptoLibrary{PQCCapable: true}
	if got := ForLibrary(lib); got != string(pqc.QuantumSafe) {
		t.Errorf("PQC-capable library = %s, want safe", got)
	}
}

func TestForLibrary_NonPQCIsVulnerable(t *testing.T) {
	lib := &model.CryptoLibrary{PQCCapable: false}
	if got := ForLibrary(lib); got != string(pqc.QuantumVulnerable) {
		t.Errorf("non-PQC library = %s, want vulnerable", got)
	}
}

func TestForConfig_ReturnsUnknown(t *testing.T) {
	cfg := &model.CryptoConfig{}
	if got := ForConfig(cfg); got != string(pqc.QuantumUnknown) {
		t.Errorf("ForConfig = %s, want unknown", got)
	}
}
