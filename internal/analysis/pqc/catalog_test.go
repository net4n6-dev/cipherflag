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

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCatalog_AllEntriesHaveNonEmptyFields asserts every canonical entry
// has non-empty Canonical, non-empty Category, and non-Unknown Status.
// A zero-value entry indicates a typo or paste error.
func TestCatalog_AllEntriesHaveNonEmptyFields(t *testing.T) {
	for key, c := range canonical {
		if c.Canonical == "" {
			t.Errorf("canonical[%q].Canonical is empty", key)
		}
		if c.Category == "" {
			t.Errorf("canonical[%q].Category is empty", key)
		}
		if c.Status == QuantumUnknown {
			t.Errorf("canonical[%q].Status is QuantumUnknown (should not appear in catalog)", key)
		}
		if c.Status == "" {
			t.Errorf("canonical[%q].Status is empty", key)
		}
	}
}

// TestCatalog_CanonicalKeyMatchesCanonicalField asserts that the map key
// and the Classification.Canonical field agree. Prevents copy-paste drift.
func TestCatalog_CanonicalKeyMatchesCanonicalField(t *testing.T) {
	for key, c := range canonical {
		if c.Canonical != key {
			t.Errorf("canonical[%q].Canonical = %q; key and field must match", key, c.Canonical)
		}
	}
}

// TestCatalog_CoveragePerFamily asserts each of the 8 categories has at
// least one entry. A regression here means someone deleted or mis-typed
// a whole family.
func TestCatalog_CoveragePerFamily(t *testing.T) {
	seen := map[Category]bool{}
	for _, c := range canonical {
		seen[c.Category] = true
	}
	for _, want := range []Category{
		CategoryAsymmetric,
		CategorySymmetric,
		CategoryHash,
		CategorySignature,
		CategoryKEX,
		CategoryKDF,
		CategoryPQCKEM,
		CategoryPQCSig,
	} {
		if !seen[want] {
			t.Errorf("no canonical entries for category %q", want)
		}
	}
}

// TestCatalog_ClassicalAsymmetricVulnerable asserts every entry with
// Category=Asymmetric has Status=Vulnerable. Classical asymmetric is
// broken by Shor's algorithm by definition.
func TestCatalog_ClassicalAsymmetricVulnerable(t *testing.T) {
	for key, c := range canonical {
		if c.Category == CategoryAsymmetric && c.Status != QuantumVulnerable {
			t.Errorf("canonical[%q] category=asymmetric but status=%v (expected Vulnerable)", key, c.Status)
		}
	}
}

// TestCatalog_PQCKEMStatus asserts every entry with Category=PQCKEM has
// Status ∈ {Safe, Hybrid}.
func TestCatalog_PQCKEMStatus(t *testing.T) {
	for key, c := range canonical {
		if c.Category == CategoryPQCKEM && c.Status != QuantumSafe && c.Status != QuantumHybrid {
			t.Errorf("canonical[%q] category=pqc-kem but status=%v (expected Safe or Hybrid)", key, c.Status)
		}
	}
}

// TestCatalog_PQCSigStatus asserts every entry with Category=PQCSig has
// Status=Safe.
func TestCatalog_PQCSigStatus(t *testing.T) {
	for key, c := range canonical {
		if c.Category == CategoryPQCSig && c.Status != QuantumSafe {
			t.Errorf("canonical[%q] category=pqc-sig but status=%v (expected Safe)", key, c.Status)
		}
	}
}

// TestSynonyms_AllResolveToCanonical asserts every value in the synonyms
// map exists as a key in the canonical map. A synonym pointing to a
// non-existent canonical name is a bug.
func TestSynonyms_AllResolveToCanonical(t *testing.T) {
	for variant, canonicalName := range synonyms {
		if _, ok := canonical[canonicalName]; !ok {
			t.Errorf("synonyms[%q] = %q but %q is not a key in canonical map", variant, canonicalName, canonicalName)
		}
	}
}

// TestSynonyms_NoCircularReferences asserts that synonym keys do not
// appear as canonical keys. Variants and canonicals must be disjoint
// sets so lookups are deterministic.
func TestSynonyms_NoCircularReferences(t *testing.T) {
	for variant := range synonyms {
		if _, ok := canonical[variant]; ok {
			t.Errorf("synonym key %q also appears in canonical map; variant and canonical sets must be disjoint", variant)
		}
	}
}

// TestSynonyms_AllKeysLowercase asserts every synonym key is already
// lowercased. The lookup path normalises input to lowercase, so uppercase
// keys in this map would be unreachable.
func TestSynonyms_AllKeysLowercase(t *testing.T) {
	for key := range synonyms {
		for _, r := range key {
			if r >= 'A' && r <= 'Z' {
				t.Errorf("synonym key %q contains uppercase; all keys must be lowercased", key)
				break
			}
		}
	}
}

// TestCanonical_AllKeysLowercase asserts every canonical key is already
// lowercased. Same reasoning as TestSynonyms_AllKeysLowercase.
func TestCanonical_AllKeysLowercase(t *testing.T) {
	for key := range canonical {
		for _, r := range key {
			if r >= 'A' && r <= 'Z' {
				t.Errorf("canonical key %q contains uppercase; all keys must be lowercased", key)
				break
			}
		}
	}
}

// TestCatalog_NewEntries validates that newly added catalog entries classify
// to the expected quantum status and category. This test drives Task 2.
func TestCatalog_NewEntries(t *testing.T) {
	cases := []struct {
		input      string
		wantStatus QuantumStatus
		wantCat    Category
	}{
		// Symmetric — weakened (128-bit effective key after Grover's)
		{"camellia-128", QuantumWeakened, CategorySymmetric},
		{"camellia-192", QuantumWeakened, CategorySymmetric},
		{"aria-128", QuantumWeakened, CategorySymmetric},
		{"aria-192", QuantumWeakened, CategorySymmetric},
		{"sm4", QuantumWeakened, CategorySymmetric},
		{"seed", QuantumWeakened, CategorySymmetric},
		// Symmetric — safe (256-bit effective key)
		{"camellia-256", QuantumSafe, CategorySymmetric},
		{"aria-256", QuantumSafe, CategorySymmetric},
		// Symmetric — vulnerable (classically broken or deprecated)
		{"blowfish", QuantumVulnerable, CategorySymmetric},
		{"rc2", QuantumVulnerable, CategorySymmetric},
		{"cast5", QuantumVulnerable, CategorySymmetric},
		{"idea", QuantumVulnerable, CategorySymmetric},
		// Hash — safe
		{"blake2b-512", QuantumSafe, CategoryHash},
		{"blake2b-384", QuantumSafe, CategoryHash},
		{"shake-256", QuantumSafe, CategoryHash},
		// Hash — weakened
		{"ripemd-160", QuantumWeakened, CategoryHash},
		{"blake3", QuantumWeakened, CategoryHash},
		{"blake2b-256", QuantumWeakened, CategoryHash},
		{"blake2s-256", QuantumWeakened, CategoryHash},
		{"sha3-224", QuantumWeakened, CategoryHash},
		{"sm3", QuantumWeakened, CategoryHash},
		{"shake-128", QuantumWeakened, CategoryHash},
		// Hash — vulnerable (classically broken)
		{"md4", QuantumVulnerable, CategoryHash},
		{"md2", QuantumVulnerable, CategoryHash},
		{"sha-0", QuantumVulnerable, CategoryHash},
		// HMAC — classified by underlying hash
		{"hmac-sha512", QuantumSafe, CategoryHash},
		{"hmac-sha384", QuantumSafe, CategoryHash},
		{"hmac-sha256", QuantumWeakened, CategoryHash},
		{"hmac-sha1", QuantumVulnerable, CategoryHash},
		{"hmac-md5", QuantumVulnerable, CategoryHash},
		// KDF additions
		{"bcrypt", QuantumSafe, CategoryKDF},
		{"ansi-x963-kdf", QuantumSafe, CategoryKDF},
		{"concat-kdf", QuantumSafe, CategoryKDF},
		{"sp800-108-kdf", QuantumSafe, CategoryKDF},
		// KEX — named curves and DH groups
		{"ecdh-p256", QuantumVulnerable, CategoryKEX},
		{"ecdh-p384", QuantumVulnerable, CategoryKEX},
		{"ecdh-p521", QuantumVulnerable, CategoryKEX},
		{"dh-2048", QuantumVulnerable, CategoryKEX},
		{"dh-3072", QuantumVulnerable, CategoryKEX},
		{"dh-4096", QuantumVulnerable, CategoryKEX},
		{"ecdh-brainpoolp256r1", QuantumVulnerable, CategoryKEX},
		// Asymmetric
		{"sm2", QuantumVulnerable, CategoryAsymmetric},
		{"ed25519ph", QuantumVulnerable, CategoryAsymmetric},
		{"ed448ph", QuantumVulnerable, CategoryAsymmetric},
		// PQC KEM candidates
		{"bike-l1", QuantumSafe, CategoryPQCKEM},
		{"bike-l3", QuantumSafe, CategoryPQCKEM},
		{"hqc-128", QuantumSafe, CategoryPQCKEM},
		{"hqc-256", QuantumSafe, CategoryPQCKEM},
		{"frodokem-640", QuantumSafe, CategoryPQCKEM},
		{"frodokem-1344", QuantumSafe, CategoryPQCKEM},
		{"ntruprime-761", QuantumSafe, CategoryPQCKEM},
		{"mceliece-348864", QuantumSafe, CategoryPQCKEM},
		// PQC Sig — SLH-DSA SHAKE variants (FIPS 205)
		{"slh-dsa-shake-128f", QuantumSafe, CategoryPQCSig},
		{"slh-dsa-shake-128s", QuantumSafe, CategoryPQCSig},
		{"slh-dsa-shake-256s", QuantumSafe, CategoryPQCSig},

		// ── 2026-04 expansion (pre-GA backfill to ~200) ──────────────
		// Named curves (all Vulnerable — ECDLP broken by Shor's).
		{"secp256k1", QuantumVulnerable, CategoryAsymmetric},
		{"secp192r1", QuantumVulnerable, CategoryAsymmetric},
		{"secp224r1", QuantumVulnerable, CategoryAsymmetric},
		{"sect283k1", QuantumVulnerable, CategoryAsymmetric},
		{"sect409k1", QuantumVulnerable, CategoryAsymmetric},
		{"sect571k1", QuantumVulnerable, CategoryAsymmetric},
		// National asymmetric standards
		{"gost-r-34.10-2012", QuantumVulnerable, CategoryAsymmetric},
		{"sm9", QuantumVulnerable, CategoryAsymmetric},
		// Stream / block cipher additions
		{"salsa20", QuantumWeakened, CategorySymmetric},
		{"chacha12", QuantumWeakened, CategorySymmetric},
		{"chacha8", QuantumVulnerable, CategorySymmetric},
		{"rc5", QuantumVulnerable, CategorySymmetric},
		{"gost-28147-89", QuantumVulnerable, CategorySymmetric},
		{"twofish", QuantumWeakened, CategorySymmetric},
		// Hash additions
		{"sha-512-224", QuantumWeakened, CategoryHash},
		{"sha-512-256", QuantumWeakened, CategoryHash},
		{"tiger", QuantumVulnerable, CategoryHash},
		{"whirlpool", QuantumSafe, CategoryHash},
		{"streebog-256", QuantumWeakened, CategoryHash},
		{"streebog-512", QuantumSafe, CategoryHash},
		{"keccak-256", QuantumWeakened, CategoryHash},
		{"keccak-512", QuantumSafe, CategoryHash},
		{"kmac-128", QuantumWeakened, CategoryHash},
		{"kmac-256", QuantumSafe, CategoryHash},
		{"hmac-sha3-256", QuantumWeakened, CategoryHash},
		{"hmac-sha3-512", QuantumSafe, CategoryHash},
		// Signature composites (Vulnerable — classical signer)
		{"sha3-256-rsa", QuantumVulnerable, CategorySignature},
		{"sha3-384-rsa", QuantumVulnerable, CategorySignature},
		{"sha3-512-rsa", QuantumVulnerable, CategorySignature},
		{"sha3-256-ecdsa", QuantumVulnerable, CategorySignature},
		{"sha3-384-ecdsa", QuantumVulnerable, CategorySignature},
		{"sha3-512-ecdsa", QuantumVulnerable, CategorySignature},
		{"shake256-rsa", QuantumVulnerable, CategorySignature},
		// KEX additions
		{"ecdh-brainpoolp224r1", QuantumVulnerable, CategoryKEX},
		{"dh-8192", QuantumVulnerable, CategoryKEX},
		{"ecdh-secp256k1", QuantumVulnerable, CategoryKEX},
		// KDF additions
		{"x9.42-kdf", QuantumSafe, CategoryKDF},
		{"hkdf-sha256", QuantumSafe, CategoryKDF},
		{"hkdf-sha384", QuantumSafe, CategoryKDF},
		// PQC KEM additions (round-3 survivors)
		{"saber", QuantumSafe, CategoryPQCKEM},
		{"ntru-hps-2048677", QuantumSafe, CategoryPQCKEM},
		{"ntru-hrss-701", QuantumSafe, CategoryPQCKEM},
		// PQC Sig additions (2024 on-ramp + SP 800-208 stateful)
		{"mayo-1", QuantumSafe, CategoryPQCSig},
		{"mayo-3", QuantumSafe, CategoryPQCSig},
		{"mayo-5", QuantumSafe, CategoryPQCSig},
		{"cross-rsdp-128-small", QuantumSafe, CategoryPQCSig},
		{"cross-rsdp-256-small", QuantumSafe, CategoryPQCSig},
		{"xmss-sha2-20-256", QuantumSafe, CategoryPQCSig},
		{"lms-sha256-m32-h25", QuantumSafe, CategoryPQCSig},
	}
	for _, tc := range cases {
		c := Classify(tc.input)
		if c.Status != tc.wantStatus {
			t.Errorf("Classify(%q).Status = %v, want %v", tc.input, c.Status, tc.wantStatus)
		}
		if c.Category != tc.wantCat {
			t.Errorf("Classify(%q).Category = %v, want %v", tc.input, c.Category, tc.wantCat)
		}
	}
}

// TestSynonyms_TLSCipherSuites verifies that compound TLS cipher suite
// strings resolve to the correct quantum classification. The test drives
// Task 4.
//
// Classification rule: weakest-link wins.
//   - ECDHE/DHE suites: KEX is the PQ concern (vulnerable)
//   - Static RSA suites: RSA key exchange (vulnerable)
//   - TLS 1.3 suites: no asymmetric KEX; symmetric cipher determines status
func TestSynonyms_TLSCipherSuites(t *testing.T) {
	cases := []struct {
		suite      string
		wantStatus QuantumStatus
	}{
		// ECDHE suites — KEX is ECDH (vulnerable)
		{"ECDHE-RSA-AES256-GCM-SHA384", QuantumVulnerable},
		{"ECDHE-ECDSA-AES256-GCM-SHA384", QuantumVulnerable},
		{"ECDHE-RSA-AES128-GCM-SHA256", QuantumVulnerable},
		{"ECDHE-RSA-CHACHA20-POLY1305", QuantumVulnerable},
		// DHE suites — KEX is DH (vulnerable)
		{"DHE-RSA-AES256-GCM-SHA384", QuantumVulnerable},
		{"DHE-RSA-AES128-GCM-SHA256", QuantumVulnerable},
		// RSA key-exchange suites (vulnerable)
		{"RSA-WITH-AES-256-CBC-SHA", QuantumVulnerable},
		{"AES256-GCM-SHA384", QuantumVulnerable},
		// TLS 1.3 suites — symmetric only
		{"TLS_AES_256_GCM_SHA384", QuantumSafe},
		{"TLS_AES_128_GCM_SHA256", QuantumWeakened},
		{"TLS_CHACHA20_POLY1305_SHA256", QuantumWeakened},
		// IANA underscore-format
		{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", QuantumVulnerable},
		{"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", QuantumVulnerable},
		{"TLS_RSA_WITH_AES_256_GCM_SHA384", QuantumVulnerable},
	}
	for _, tc := range cases {
		c := Classify(tc.suite)
		if c.Status != tc.wantStatus {
			t.Errorf("Classify(%q).Status = %v, want %v", tc.suite, c.Status, tc.wantStatus)
		}
	}
}

// TestClassify_SecurityLevelOnStandardizedPQC asserts that the 18 NIST-
// standardised PQC entries (ML-KEM, ML-DSA, SLH-DSA) carry the correct
// NIST security level per FIPS 203/204/205.
func TestClassify_SecurityLevelOnStandardizedPQC(t *testing.T) {
	cases := []struct {
		name      string
		wantLevel uint8
	}{
		// NIST PQC categories per FIPS 203/204/205:
		{"ml-kem-512", 1},
		{"ml-kem-768", 3},
		{"ml-kem-1024", 5},
		{"ml-dsa-44", 2},
		{"ml-dsa-65", 3},
		{"ml-dsa-87", 5},
		{"slh-dsa-sha2-128s", 1},
		{"slh-dsa-sha2-128f", 1},
		{"slh-dsa-sha2-192s", 3},
		{"slh-dsa-sha2-256s", 5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Classify(tc.name)
			require.Equal(t, tc.wantLevel, c.SecurityLevel, "expected NIST level %d for %q", tc.wantLevel, tc.name)
		})
	}
}

// TestClassify_SecurityLevelZeroForClassical asserts that classical algorithms
// have SecurityLevel == 0 (the field does not apply to non-PQC entries).
func TestClassify_SecurityLevelZeroForClassical(t *testing.T) {
	for _, name := range []string{"rsa", "ecdsa", "ed25519", "aes-256", "sha256"} {
		t.Run(name, func(t *testing.T) {
			c := Classify(name)
			require.Equal(t, uint8(0), c.SecurityLevel, "classical algo %q should have zero security level", name)
		})
	}
}

// TestSynonyms_PQCAliasExpansion verifies new pre-standardisation PQC aliases.
func TestSynonyms_PQCAliasExpansion(t *testing.T) {
	cases := []struct {
		alias      string
		wantStatus QuantumStatus
	}{
		{"sphincs+-sha256-128f-simple", QuantumSafe},
		{"sphincs+-sha256-256s-simple", QuantumSafe},
		{"sphincs+-shake-192f-simple", QuantumSafe},
		{"sphincs+-shake-192s-simple", QuantumSafe},
		{"crystals-kyber", QuantumSafe},
		{"crystals-dilithium", QuantumSafe},
		{"kyber", QuantumSafe},
		// 2026-04 expansion — PQC short-name aliases
		{"ntru-hps", QuantumSafe},
		{"ntru-hrss", QuantumSafe},
		{"mayo", QuantumSafe},
		{"cross", QuantumSafe},
		{"xmss", QuantumSafe},
		{"lms", QuantumSafe},
		// Curve / SSH / GOST / SHA-trunc aliases resolve to Vulnerable or
		// Weakened depending on what they resolve to.
		{"p-192", QuantumVulnerable},
		{"arcfour256", QuantumVulnerable},
		{"hmac-sha2-512", QuantumSafe},
		{"gost3411-2012-512", QuantumSafe},
		{"sha-512/256", QuantumWeakened},
	}
	for _, tc := range cases {
		c := Classify(tc.alias)
		if c.Status != tc.wantStatus {
			t.Errorf("Classify(%q).Status = %v, want %v", tc.alias, c.Status, tc.wantStatus)
		}
	}
}
