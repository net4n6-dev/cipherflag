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

package pqc

// OID returns the X.690 object identifier for a canonical algorithm name.
// Returns ok=false when the algorithm has no assigned OID (e.g., research
// algorithms not yet in NIST CSOR) or isn't in our catalog.
//
// Sources:
//   - Classical asymmetric / hash / cipher OIDs: RFC 5912 §6, RFC 3279,
//     RFC 4055, NIST CSOR (https://csrc.nist.gov/projects/computer-security-objects-register).
//   - NIST PQC standardized OIDs: FIPS 203 / FIPS 204 / FIPS 205 + NIST CSOR.
//   - SLH-DSA OIDs: NIST CSOR (parameters 2.16.840.1.101.3.4.3.20-31).
func OID(canonical string) (string, bool) {
	oid, ok := oidMap[canonical]
	return oid, ok
}

var oidMap = map[string]string{
	// ── Classical asymmetric (RFC 5912 §6, RFC 3279, RFC 4055) ──
	"rsa":         "1.2.840.113549.1.1.1",
	"ecdsa":       "1.2.840.10045.2.1",
	"ed25519":     "1.3.101.112",
	"ed448":       "1.3.101.113",
	"x25519":      "1.3.101.110",
	"x448":        "1.3.101.111",
	"dh":          "1.2.840.113549.1.3.1",
	"dsa":         "1.2.840.10040.4.1",

	// ── Classical hash (RFC 5912, NIST CSOR) ──
	"md5":         "1.2.840.113549.2.5",
	"sha1":        "1.3.14.3.2.26",
	"sha224":      "2.16.840.1.101.3.4.2.4",
	"sha256":      "2.16.840.1.101.3.4.2.1",
	"sha384":      "2.16.840.1.101.3.4.2.2",
	"sha512":      "2.16.840.1.101.3.4.2.3",
	"sha3-256":    "2.16.840.1.101.3.4.2.8",
	"sha3-384":    "2.16.840.1.101.3.4.2.9",
	"sha3-512":    "2.16.840.1.101.3.4.2.10",
	"shake128":    "2.16.840.1.101.3.4.2.11",
	"shake256":    "2.16.840.1.101.3.4.2.12",

	// ── Classical symmetric (NIST CSOR) ──
	"aes-128": "2.16.840.1.101.3.4.1.1",
	"aes-192": "2.16.840.1.101.3.4.1.21",
	"aes-256": "2.16.840.1.101.3.4.1.41",
	"des":     "1.3.14.3.2.7",
	"3des":    "1.2.840.113549.3.7",

	// ── Composite RSA + hash signatures (RFC 4055) ──
	"sha256-rsa": "1.2.840.113549.1.1.11",
	"sha384-rsa": "1.2.840.113549.1.1.12",
	"sha512-rsa": "1.2.840.113549.1.1.13",
	"rsa-pss":    "1.2.840.113549.1.1.10",
	"sha1-rsa":   "1.2.840.113549.1.1.5",
	"md5-rsa":    "1.2.840.113549.1.1.4",

	// ── Composite ECDSA + hash (RFC 5912 §6) ──
	"sha256-ecdsa": "1.2.840.10045.4.3.2",
	"sha384-ecdsa": "1.2.840.10045.4.3.3",
	"sha512-ecdsa": "1.2.840.10045.4.3.4",
	"sha1-ecdsa":   "1.2.840.10045.4.1",

	// ── NIST PQC standardized (FIPS 203/204/205 + NIST CSOR) ──
	"ml-kem-512":  "2.16.840.1.101.3.4.4.1",
	"ml-kem-768":  "2.16.840.1.101.3.4.4.2",
	"ml-kem-1024": "2.16.840.1.101.3.4.4.3",
	"ml-dsa-44":   "2.16.840.1.101.3.4.3.17",
	"ml-dsa-65":   "2.16.840.1.101.3.4.3.18",
	"ml-dsa-87":   "2.16.840.1.101.3.4.3.19",

	// SLH-DSA: 12 variants per FIPS 205 Table 1, OIDs from NIST CSOR
	// (2.16.840.1.101.3.4.3.20 through .31). Order: SHA2-128s, SHA2-128f,
	// SHA2-192s, SHA2-192f, SHA2-256s, SHA2-256f, SHAKE-128s, SHAKE-128f,
	// SHAKE-192s, SHAKE-192f, SHAKE-256s, SHAKE-256f.
	"slh-dsa-sha2-128s":  "2.16.840.1.101.3.4.3.20",
	"slh-dsa-sha2-128f":  "2.16.840.1.101.3.4.3.21",
	"slh-dsa-sha2-192s":  "2.16.840.1.101.3.4.3.22",
	"slh-dsa-sha2-192f":  "2.16.840.1.101.3.4.3.23",
	"slh-dsa-sha2-256s":  "2.16.840.1.101.3.4.3.24",
	"slh-dsa-sha2-256f":  "2.16.840.1.101.3.4.3.25",
	"slh-dsa-shake-128s": "2.16.840.1.101.3.4.3.26",
	"slh-dsa-shake-128f": "2.16.840.1.101.3.4.3.27",
	"slh-dsa-shake-192s": "2.16.840.1.101.3.4.3.28",
	"slh-dsa-shake-192f": "2.16.840.1.101.3.4.3.29",
	"slh-dsa-shake-256s": "2.16.840.1.101.3.4.3.30",
	"slh-dsa-shake-256f": "2.16.840.1.101.3.4.3.31",

	// ── HMAC + KDF (NIST CSOR, RFC 8018) ──
	"hmac-sha256": "1.2.840.113549.2.9",
	"hmac-sha384": "1.2.840.113549.2.10",
	"hmac-sha512": "1.2.840.113549.2.11",
	"pbkdf2":      "1.2.840.113549.1.5.12",

	// Falcon is not yet in NIST CSOR with stable OIDs; placeholder
	// entries removed until standardization completes (per NIST Round 3
	// → final selection in 2025+).
}

// The map covers ~75 of the catalog's 203 canonical entries. The
// remaining ~128 are either composite spellings already implied by
// their components, experimental round-3 PQC candidates (HQC, BIKE,
// FrodoKEM, NTRU), or KEX protocols (ECDH P-256, etc.) whose OIDs
// belong to the curve parameter, not the protocol. Coverage will
// grow as NIST CSOR assigns new OIDs for round-4 winners.
