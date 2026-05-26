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
	"github.com/net4n6-dev/cipherflag/internal/analysis/pqc"
	"github.com/net4n6-dev/cipherflag/internal/model"
)

// ForCertificate returns the PQC status string for a cert based on its
// key algorithm.
func ForCertificate(cert *model.Certificate) string {
	return string(pqc.StatusOf(string(cert.KeyAlgorithm)))
}

// ForSSHKey returns the PQC status string for an SSH key based on its
// key type. SSH types like "ssh-rsa" resolve via pqc.synonyms to
// classical asymmetric algorithms (Vulnerable).
func ForSSHKey(k *model.SSHKey) string {
	return string(pqc.StatusOf(k.KeyType))
}

// ForLibrary returns Safe if PQCCapable, Vulnerable otherwise. Libraries
// don't have a single algorithm field — PQCCapable is a library-level
// claim recorded during discovery.
func ForLibrary(lib *model.CryptoLibrary) string {
	if lib.PQCCapable {
		return string(pqc.QuantumSafe)
	}
	return string(pqc.QuantumVulnerable)
}

// ForConfig returns Unknown — per-algorithm analysis belongs to CFG-003
// findings, not a single aggregate status. 4.3 Compliance may revisit.
func ForConfig(cfg *model.CryptoConfig) string {
	return string(pqc.QuantumUnknown)
}

// ForProtocol returns Unknown in v1 — protocol observations don't yet
// carry a PQC kex signal that lets us make an aggregate claim. Per-
// algorithm analysis lives in the PROTO findings, not an aggregate
// PQCStatus. Revisit when PQC-aware cipher suite detection ships.
func ForProtocol(ep *model.ProtocolEndpoint) string {
	return string(pqc.QuantumUnknown)
}
