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

// Package pqc classifies cryptographic algorithms by their quantum-
// resistance status. It is the foundation for Layer 4 intelligence
// (scoring, compliance, risk prioritization) and consumed wherever an
// algorithm string needs to be interpreted.
//
// The module is pure data: no database, no network, no state. Safe to
// call thousands of times per scoring cycle.
//
// Unknown inputs are not errors — they return Classification{Status:
// QuantumUnknown} so callers can emit an info-level finding prompting a
// taxonomy extension.
package pqc

// QuantumStatus is the quantum-resistance classification of an algorithm.
type QuantumStatus string

const (
	// QuantumVulnerable — broken by Shor's algorithm (classical asymmetric:
	// RSA, ECDSA, DH, etc.) or cryptanalytically broken regardless of
	// quantum (MD5, SHA-1, DES, RC4, 3DES).
	QuantumVulnerable QuantumStatus = "vulnerable"

	// QuantumWeakened — effective strength halved by Grover's algorithm.
	// 128-bit symmetric ciphers and 256-bit hashes fall here.
	QuantumWeakened QuantumStatus = "weakened"

	// QuantumSafe — NIST PQC standard, or symmetric ≥256-bit key, or hash
	// ≥384-bit digest. Meets the post-quantum-safe bar.
	QuantumSafe QuantumStatus = "safe"

	// QuantumHybrid — combined classical + PQC KEM (e.g., X25519-ML-KEM-768).
	// Treated as a distinct status because its safety properties depend on
	// at least one of the two being unbroken.
	QuantumHybrid QuantumStatus = "hybrid"

	// QuantumUnknown — algorithm not found in the taxonomy. Callers should
	// treat this as a signal to extend the catalog, not as a positive or
	// negative classification.
	QuantumUnknown QuantumStatus = "unknown"
)

// Category is the algorithm family.
type Category string

const (
	CategoryAsymmetric Category = "asymmetric" // classical public-key (RSA, ECDSA, Ed25519, …)
	CategorySymmetric  Category = "symmetric"  // block/stream ciphers (AES, ChaCha20, DES, …)
	CategoryHash       Category = "hash"       // SHA-*, MD5
	CategorySignature  Category = "signature"  // composite signatures (SHA256-RSA, SHA384-ECDSA, …)
	CategoryKEX        Category = "kex"        // key exchange (ECDH, DH groups, curve25519-sha256, …)
	CategoryKDF        Category = "kdf"        // key derivation (PBKDF2, scrypt, argon2, …)
	CategoryPQCKEM     Category = "pqc-kem"    // post-quantum KEMs (ML-KEM, hybrids)
	CategoryPQCSig     Category = "pqc-sig"    // post-quantum signatures (ML-DSA, SLH-DSA, FALCON)
)

// Classification is the result of looking up an algorithm name. For
// recognised inputs, all three fields are non-empty. For unknown inputs,
// Status is QuantumUnknown and Canonical/Category are empty strings.
type Classification struct {
	Status    QuantumStatus
	Canonical string
	Category  Category
	// SecurityLevel is the NIST PQC standardization security category
	// (1–5 per the NIST PQC project's criteria mapping each level to
	// an analogous classical algorithm's strength). Zero for classical
	// algorithms (the field doesn't apply).
	SecurityLevel uint8

	// Source is the upstream URL pointing at this entry's authoritative
	// record (NIST FIPS PDF, IETF draft) or the literal "manual" for
	// hand-curated entries. Populated by the catalog refresh generator
	// (scripts/catalogs/refresh-pqc.go); empty for QuantumUnknown.
	Source string
}
