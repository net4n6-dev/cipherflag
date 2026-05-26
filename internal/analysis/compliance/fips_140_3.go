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

package compliance

import (
	"strings"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

// fipsApprovedKeyAlgorithms — classical NIST-approved asymmetric
// primitives (lowercased). Ed25519/Ed448/X25519/X448 are NOT on the
// FIPS 140-3 list despite cryptographic strength.
var fipsApprovedKeyAlgorithms = map[string]bool{
	"rsa":   true,
	"ecdsa": true,
	"dsa":   true, // still listed by CMVP for legacy validation
}

// fipsApprovedSSHKeyTypes — SSH key types aligned to the FIPS allowlist.
var fipsApprovedSSHKeyTypes = map[string]bool{
	"ssh-rsa":             true,
	"rsa-sha2-256":        true,
	"rsa-sha2-512":        true,
	"ecdsa-sha2-nistp256": true,
	"ecdsa-sha2-nistp384": true,
	"ecdsa-sha2-nistp521": true,
}

// fipsApprovedHashes — approved hash functions for cert signatures.
// MD5 and SHA-1 are explicitly excluded.
var fipsApprovedHashes = map[string]bool{
	"sha-224":  true,
	"sha-256":  true,
	"sha-384":  true,
	"sha-512":  true,
	"sha3-224": true,
	"sha3-256": true,
	"sha3-384": true,
	"sha3-512": true,
}

func normaliseFIPS(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// evaluateFIPS140_3Certificate — strict algorithm allowlist + finding
// severity. Ed25519 is NOT FIPS-approved despite its cryptographic
// strength.
func evaluateFIPS140_3Certificate(r *model.AssetHealthReport, cert *model.Certificate) string {
	// Direct check 1: KeyAlgorithm must be on the FIPS allowlist.
	if !fipsApprovedKeyAlgorithms[normaliseFIPS(string(cert.KeyAlgorithm))] {
		return StatusFail
	}

	// Direct check 2: Signature algorithm must use a FIPS-approved hash.
	if hashKey := extractFIPSHashKey(string(cert.SignatureAlgorithm)); hashKey != "" {
		if !fipsApprovedHashes[hashKey] {
			return StatusFail
		}
	}

	// Finding-severity filter: fail on Critical/High in crypto categories.
	cryptoCats := []model.FindingCategory{
		model.CategoryKeyStrength,
		model.CategoryCipher,
		model.CategorySignature,
	}
	if hasSeverityInCategories(r.Findings,
		[]model.Severity{model.SeverityCritical, model.SeverityHigh},
		cryptoCats) {
		return StatusFail
	}
	if hasSeverityInCategories(r.Findings,
		[]model.Severity{model.SeverityMedium},
		cryptoCats) {
		return StatusPartial
	}
	return StatusPass
}

// evaluateFIPS140_3SSHKey — SSH key type allowlist.
func evaluateFIPS140_3SSHKey(r *model.AssetHealthReport, k *model.SSHKey) string {
	if !fipsApprovedSSHKeyTypes[normaliseFIPS(k.KeyType)] {
		return StatusFail
	}
	if hasRuleID(r.Findings, "SSH-001", "SSH-002") {
		return StatusFail
	}
	if hasRuleID(r.Findings, "SSH-003") {
		return StatusPartial
	}
	return StatusPass
}

// evaluateFIPS140_3Library — binary: LIB-005 present (FIPS-validated) or
// absent (not validated).
func evaluateFIPS140_3Library(r *model.AssetHealthReport) string {
	if hasRuleID(r.Findings, "LIB-005") {
		return StatusPass
	}
	return StatusFail
}

// extractFIPSHashKey derives the canonical FIPS hash-map key from a
// signature algorithm name. Handles both camelCase forms used by the
// model (SHA256WithRSA, ECDSAWithSHA256, SHA1WithRSA) and hyphenated
// forms sometimes seen in other sources (SHA256-RSA, sha-256-rsa).
//
// Returns empty string if sigAlg is empty or unrecognisable — caller
// should treat that as "no hash info" (skip the hash check).
func extractFIPSHashKey(sigAlg string) string {
	s := normaliseFIPS(sigAlg)
	if s == "" {
		return ""
	}
	// camelCase forms: "sha256withrsa", "sha384withrsa", "ecdsawithsha256",
	// "md5withrsa", "ed25519" (no "with" — returned as-is, will miss map).
	if idx := strings.Index(s, "with"); idx != -1 {
		before := s[:idx]  // e.g. "sha256", "ecdsa", "md5"
		after := s[idx+4:] // e.g. "rsa", "sha256"
		// Prefer the component that starts with "sha" or "md" — that's the hash.
		if strings.HasPrefix(after, "sha") || strings.HasPrefix(after, "md") {
			s = after
		} else {
			s = before
		}
	} else if idx := strings.LastIndex(s, "-"); idx > 0 {
		// Hyphenated form: trim trailing key-algo token.
		s = s[:idx]
	}
	// Insert hyphen: "sha256" → "sha-256", leave "sha3-256" and "sha-256" alone.
	if strings.HasPrefix(s, "sha") && !strings.HasPrefix(s, "sha-") && !strings.HasPrefix(s, "sha3-") {
		s = "sha-" + s[3:]
	}
	return s
}

// evaluateFIPS140_3Config — hard-fail on CFG-001 (legacy provider) and
// CFG-003 (weak ciphers/MACs/kex).
func evaluateFIPS140_3Config(r *model.AssetHealthReport) string {
	if hasRuleID(r.Findings, "CFG-001", "CFG-003") {
		return StatusFail
	}
	if hasSeverityIn(r.Findings, model.SeverityMedium) {
		return StatusPartial
	}
	return StatusPass
}

// evaluateFIPS140_3Protocol — TLS endpoints require MinTLSVersion ≥ 1.2
// with no weak ciphers/null/export. SSH endpoints require empty weak
// kex/cipher/MAC arrays.
func evaluateFIPS140_3Protocol(r *model.AssetHealthReport, ep *model.ProtocolEndpoint) string {
	if ep == nil {
		return StatusUnknown
	}
	if strings.EqualFold(ep.Protocol, "TLS") {
		if ep.HasNullExportCipher {
			return StatusFail
		}
		switch ep.MinTLSVersionSeen {
		case "SSL 3.0", "TLS 1.0", "TLS 1.1":
			return StatusFail
		}
		if len(ep.WeakCipherSeen) > 0 {
			return StatusFail
		}
		return StatusPass
	}
	// SSH: weak kex/cipher/MAC → fail; SSHv1 → fail.
	if ep.HasSSHv1 || len(ep.WeakKexSeen) > 0 || len(ep.WeakCipherSeen) > 0 || len(ep.WeakMacSeen) > 0 {
		return StatusFail
	}
	return StatusPass
}
