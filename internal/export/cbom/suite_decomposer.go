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

package cbom

import "strings"

// SuiteDecomposition is the structured view of a TLS cipher suite name.
// Empty fields indicate the suite doesn't specify that component (e.g.,
// TLS 1.3 suites omit KEX + Sig because they're negotiated separately).
type SuiteDecomposition struct {
	Bulk       string // canonical bulk-cipher algo name (aes-128, aes-256, chacha20-poly1305, …)
	Mode       string // block-cipher mode if applicable (gcm, cbc, ccm; empty for stream ciphers)
	Hash       string // hash function (sha256, sha384, sha1, md5, …)
	KEX        string // key exchange method (ecdhe, dhe, rsa, …) — TLS 1.2 only
	Sig        string // signature algorithm (rsa, ecdsa, dsa) — TLS 1.2 only
	Recognized bool   // true if at least one field was populated from a known table
}

// DecomposeTLSSuite parses an IANA TLS cipher suite name into its
// canonical components. Returns Recognized=false (with empty fields)
// for unknown suites. The output's Bulk + Hash fields are used by the
// CBOM emit path to seed protocol→algorithm Dependencies (W1) and to
// populate the algorithm component's `mode` field (W2).
func DecomposeTLSSuite(name string) SuiteDecomposition {
	n := strings.ToUpper(name)
	if !strings.HasPrefix(n, "TLS_") {
		return SuiteDecomposition{}
	}
	rest := strings.TrimPrefix(n, "TLS_")
	parts := strings.Split(rest, "_")

	d := SuiteDecomposition{}

	// TLS 1.3 form: AES_128_GCM_SHA256, CHACHA20_POLY1305_SHA256, AES_256_GCM_SHA384
	if !contains(parts, "WITH") {
		d = decomposeTLS13(parts)
		d.Recognized = d.Bulk != "" || d.Hash != ""
		return d
	}

	// TLS 1.2 form: <KEX>_<SIG>_WITH_<BULK>_<MODE?>_<HASH>
	withIdx := indexOf(parts, "WITH")
	if withIdx < 0 {
		return d
	}
	kexSig := parts[:withIdx]
	bulkRest := parts[withIdx+1:]

	switch len(kexSig) {
	case 1: // RSA — kex == sig
		d.KEX = strings.ToLower(kexSig[0])
		d.Sig = d.KEX
	case 2:
		d.KEX = strings.ToLower(kexSig[0])
		d.Sig = strings.ToLower(kexSig[1])
	}

	d = mergeBulkHash(d, bulkRest)
	d.Recognized = d.Bulk != "" && d.Hash != ""
	return d
}

func decomposeTLS13(parts []string) SuiteDecomposition {
	d := SuiteDecomposition{}
	// Last element is always the hash. Everything before is bulk+mode.
	if len(parts) < 2 {
		return d
	}
	candidate := parts[:len(parts)-1]
	hashToken := parts[len(parts)-1]
	// CHACHA20_POLY1305 → chacha20-poly1305 (no separate mode)
	if len(candidate) == 2 && candidate[0] == "CHACHA20" && candidate[1] == "POLY1305" {
		d.Bulk = "chacha20-poly1305"
		d.Hash = normalizeHash(hashToken)
		return d
	}
	// AES_128_GCM, AES_256_GCM
	if len(candidate) == 3 && candidate[0] == "AES" {
		d.Bulk = "aes-" + strings.ToLower(candidate[1])
		d.Mode = strings.ToLower(candidate[2])
		d.Hash = normalizeHash(hashToken)
		return d
	}
	// Unknown bulk structure — leave all fields empty (Recognized=false).
	return d
}

func mergeBulkHash(d SuiteDecomposition, parts []string) SuiteDecomposition {
	if len(parts) == 0 {
		return d
	}
	d.Hash = normalizeHash(parts[len(parts)-1])
	rest := parts[:len(parts)-1]
	// Special: CHACHA20_POLY1305 with no mode
	if len(rest) == 2 && rest[0] == "CHACHA20" && rest[1] == "POLY1305" {
		d.Bulk = "chacha20-poly1305"
		return d
	}
	// AES_128_GCM, AES_256_CBC, etc.
	if len(rest) == 3 && rest[0] == "AES" {
		d.Bulk = "aes-" + strings.ToLower(rest[1])
		d.Mode = strings.ToLower(rest[2])
		return d
	}
	// 3DES_EDE_CBC, etc. — fold all but last into Bulk, last is mode
	if len(rest) >= 2 {
		d.Bulk = strings.ToLower(strings.Join(rest[:len(rest)-1], "-"))
		d.Mode = strings.ToLower(rest[len(rest)-1])
		return d
	}
	if len(rest) == 1 {
		d.Bulk = strings.ToLower(rest[0])
	}
	return d
}

func contains(slice []string, target string) bool {
	for _, s := range slice {
		if s == target {
			return true
		}
	}
	return false
}

// normalizeHash canonicalises the hash token from an IANA suite name.
// IANA uses bare "SHA" as shorthand for SHA-1 (RFC 5246 Appendix A.5);
// all other tokens are already canonical (SHA256, SHA384, MD5, …).
func normalizeHash(token string) string {
	if strings.ToUpper(token) == "SHA" {
		return "sha1"
	}
	return strings.ToLower(token)
}

func indexOf(slice []string, target string) int {
	for i, s := range slice {
		if s == target {
			return i
		}
	}
	return -1
}
