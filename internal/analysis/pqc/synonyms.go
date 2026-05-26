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

// synonyms maps variant spellings to their canonical name. Lookups flow
// through Classify which checks synonyms first, then falls through to
// canonical.
//
// Add a variant here rather than in canonical whenever a new spelling of
// an already-catalogued algorithm appears. If a genuinely new algorithm
// appears, add it to canonical.
//
// Keys must be lowercased (Classify normalises input before lookup).
// Values must be present as keys in the canonical map — see
// TestSynonyms_AllResolveToCanonical in catalog_test.go.
var synonyms = map[string]string{
	// ── RSA variants ───────────────────────────────────────────────
	"ssh-rsa":       "rsa",
	"rsaencryption": "rsa",
	"rsa-1024":      "rsa",
	"rsa-2048":      "rsa",
	"rsa-3072":      "rsa",
	"rsa-4096":      "rsa",
	"rsa-pss":       "rsa",
	"rsassa-pss":    "rsa",

	// ── DSA variants ───────────────────────────────────────────────
	"ssh-dss": "dsa",
	"id-dsa":  "dsa",

	// ── ECDSA variants (curve dropped — same classification) ───────
	"ecdsa-sha2-nistp256": "ecdsa",
	"ecdsa-sha2-nistp384": "ecdsa",
	"ecdsa-sha2-nistp521": "ecdsa",
	"id-ecpublickey":      "ecdsa",
	"ecdsa-p256":          "ecdsa",
	"ecdsa-p384":          "ecdsa",
	"ecdsa-p521":          "ecdsa",

	// ── Ed25519 / Ed448 variants ───────────────────────────────────
	"ssh-ed25519": "ed25519",
	"ssh-ed448":   "ed448",
	"id-ed25519":  "ed25519",
	"id-ed448":    "ed448",

	// ── DH variants ────────────────────────────────────────────────
	"diffie-hellman": "dh",
	"id-dh":          "dh",

	// ── AES spelling variants ──────────────────────────────────────
	"aes128":     "aes-128",
	"aes192":     "aes-192",
	"aes256":     "aes-256",
	"aes128-gcm": "aes-128-gcm",
	"aes192-gcm": "aes-192-gcm",
	"aes256-gcm": "aes-256-gcm",
	"aes128-cbc": "aes-128-cbc",
	"aes192-cbc": "aes-192-cbc",
	"aes256-cbc": "aes-256-cbc",
	"aes128-ctr": "aes-128-ctr",
	"aes256-ctr": "aes-256-ctr",
	"aes128_gcm": "aes-128-gcm",
	"aes256_gcm": "aes-256-gcm",

	// ── X.509 / PKIX OID-name signature variants ───────────────────
	// Certificate signature_algorithm fields frequently carry these
	// RFC-style names rather than the short form.
	"md5withrsaencryption":    "md5-rsa",
	"md5withrsa":              "md5-rsa",
	"sha1withrsaencryption":   "sha1-rsa",
	"sha1withrsa":             "sha1-rsa",
	"sha224withrsaencryption": "sha224-rsa",
	"sha256withrsaencryption": "sha256-rsa",
	"sha384withrsaencryption": "sha384-rsa",
	"sha512withrsaencryption": "sha512-rsa",
	"ecdsa-with-sha1":         "sha1-ecdsa",
	"ecdsa-with-sha224":       "sha224-ecdsa",
	"ecdsa-with-sha256":       "sha256-ecdsa",
	"ecdsa-with-sha384":       "sha384-ecdsa",
	"ecdsa-with-sha512":       "sha512-ecdsa",
	"dsa-with-sha1":           "sha1-dsa",

	// ── Hash spelling variants ─────────────────────────────────────
	"sha1":     "sha-1",
	"sha224":   "sha-224",
	"sha256":   "sha-256",
	"sha384":   "sha-384",
	"sha512":   "sha-512",
	"sha3_256": "sha3-256",
	"sha3_384": "sha3-384",
	"sha3_512": "sha3-512",

	// ── PQC pre-standardisation names ──────────────────────────────
	"kyber512":   "ml-kem-512",
	"kyber768":   "ml-kem-768",
	"kyber1024":  "ml-kem-1024",
	"dilithium2": "ml-dsa-44",
	"dilithium3": "ml-dsa-65",
	"dilithium5": "ml-dsa-87",
	"sphincs+":   "slh-dsa-sha2-128f",

	// ── 3DES spellings ─────────────────────────────────────────────
	"3des-cbc":          "3des",
	"des-ede3-cbc":      "3des",
	"triple-des":        "3des",

	// ── ChaCha20 spellings ─────────────────────────────────────────
	"chacha20_poly1305": "chacha20-poly1305",
	"chachapoly":        "chacha20-poly1305",

	// ── TLS 1.2 cipher suites — ECDHE variants → ecdh-p256 ───────────────────
	// KEX is the PQ-relevant component; cipher + hash are secondary.
	"ecdhe-rsa-aes256-gcm-sha384":      "ecdh-p256",
	"ecdhe-ecdsa-aes256-gcm-sha384":    "ecdh-p256",
	"ecdhe-rsa-aes256-sha384":          "ecdh-p256",
	"ecdhe-ecdsa-aes256-sha384":        "ecdh-p256",
	"ecdhe-rsa-aes256-sha":             "ecdh-p256",
	"ecdhe-ecdsa-aes256-sha":           "ecdh-p256",
	"ecdhe-rsa-aes128-gcm-sha256":      "ecdh-p256",
	"ecdhe-ecdsa-aes128-gcm-sha256":    "ecdh-p256",
	"ecdhe-rsa-aes128-sha256":          "ecdh-p256",
	"ecdhe-ecdsa-aes128-sha256":        "ecdh-p256",
	"ecdhe-rsa-aes128-sha":             "ecdh-p256",
	"ecdhe-ecdsa-aes128-sha":           "ecdh-p256",
	"ecdhe-rsa-chacha20-poly1305":      "ecdh-p256",
	"ecdhe-ecdsa-chacha20-poly1305":    "ecdh-p256",
	"ecdhe-rsa-des-cbc3-sha":           "ecdh-p256",
	"ecdhe-ecdsa-des-cbc3-sha":         "ecdh-p256",
	"ecdhe-rsa-rc4-sha":                "ecdh-p256",
	"ecdhe-ecdsa-rc4-sha":              "ecdh-p256",
	"ecdhe-rsa-camellia256-sha384":     "ecdh-p256",
	"ecdhe-ecdsa-camellia256-sha384":   "ecdh-p256",
	"ecdhe-rsa-camellia128-sha256":     "ecdh-p256",
	"ecdhe-ecdsa-camellia128-sha256":   "ecdh-p256",

	// ── TLS 1.2 cipher suites — DHE variants → dh ────────────────────────────
	"dhe-rsa-aes256-gcm-sha384":        "dh",
	"dhe-rsa-aes128-gcm-sha256":        "dh",
	"dhe-rsa-aes256-sha256":            "dh",
	"dhe-rsa-aes128-sha256":            "dh",
	"dhe-rsa-aes256-sha":               "dh",
	"dhe-rsa-aes128-sha":               "dh",
	"dhe-rsa-chacha20-poly1305":        "dh",
	"dhe-rsa-des-cbc3-sha":             "dh",
	"dhe-dss-aes256-gcm-sha384":        "dh",
	"dhe-dss-aes128-gcm-sha256":        "dh",
	"dhe-dss-aes256-sha256":            "dh",
	"dhe-dss-aes128-sha256":            "dh",
	"dhe-dss-aes256-sha":               "dh",
	"dhe-dss-aes128-sha":               "dh",
	"edh-rsa-des-cbc3-sha":             "dh",
	"edh-dss-des-cbc3-sha":             "dh",

	// ── TLS 1.2 cipher suites — RSA key exchange → rsa ───────────────────────
	"aes256-gcm-sha384":                "rsa",
	"aes128-gcm-sha256":                "rsa",
	"aes256-sha256":                    "rsa",
	"aes128-sha256":                    "rsa",
	"aes256-sha":                       "rsa",
	"aes128-sha":                       "rsa",
	"des-cbc3-sha":                     "rsa",
	"rc4-sha":                          "rsa",
	"rc4-md5":                          "rsa",
	"rsa-with-aes-256-gcm-sha384":      "rsa",
	"rsa-with-aes-128-gcm-sha256":      "rsa",
	"rsa-with-aes-256-cbc-sha256":      "rsa",
	"rsa-with-aes-128-cbc-sha256":      "rsa",
	"rsa-with-aes-256-cbc-sha":         "rsa",
	"rsa-with-aes-128-cbc-sha":         "rsa",
	"rsa-with-3des-ede-cbc-sha":        "rsa",
	"rsa-with-rc4-128-sha":             "rsa",
	"rsa-with-rc4-128-md5":             "rsa",

	// ── TLS 1.3 suites — symmetric cipher is the PQ-relevant component ───────
	"tls_aes_256_gcm_sha384":           "aes-256-gcm",   // Safe
	"tls_aes_128_gcm_sha256":           "aes-128-gcm",   // Weakened
	"tls_chacha20_poly1305_sha256":     "chacha20-poly1305", // Weakened
	"tls_aes_128_ccm_sha256":           "aes-128-ccm",   // Weakened
	"tls_aes_128_ccm_8_sha256":         "aes-128-ccm",   // Weakened

	// ── IANA underscore-format (TLS 1.2) — same classification as above ───────
	"tls_ecdhe_rsa_with_aes_256_gcm_sha384":        "ecdh-p256",
	"tls_ecdhe_ecdsa_with_aes_256_gcm_sha384":      "ecdh-p256",
	"tls_ecdhe_rsa_with_aes_128_gcm_sha256":        "ecdh-p256",
	"tls_ecdhe_ecdsa_with_aes_128_gcm_sha256":      "ecdh-p256",
	"tls_ecdhe_rsa_with_chacha20_poly1305_sha256":  "ecdh-p256",
	"tls_ecdhe_ecdsa_with_chacha20_poly1305_sha256": "ecdh-p256",
	"tls_ecdhe_rsa_with_aes_256_cbc_sha384":        "ecdh-p256",
	"tls_ecdhe_ecdsa_with_aes_256_cbc_sha384":      "ecdh-p256",
	"tls_ecdhe_rsa_with_aes_128_cbc_sha256":        "ecdh-p256",
	"tls_ecdhe_ecdsa_with_aes_128_cbc_sha256":      "ecdh-p256",
	"tls_ecdhe_rsa_with_3des_ede_cbc_sha":          "ecdh-p256",
	"tls_dhe_rsa_with_aes_256_gcm_sha384":          "dh",
	"tls_dhe_rsa_with_aes_128_gcm_sha256":          "dh",
	"tls_dhe_rsa_with_chacha20_poly1305_sha256":    "dh",
	"tls_dhe_rsa_with_aes_256_cbc_sha256":          "dh",
	"tls_dhe_rsa_with_aes_128_cbc_sha256":          "dh",
	"tls_rsa_with_aes_256_gcm_sha384":              "rsa",
	"tls_rsa_with_aes_128_gcm_sha256":              "rsa",
	"tls_rsa_with_aes_256_cbc_sha256":              "rsa",
	"tls_rsa_with_aes_128_cbc_sha256":              "rsa",
	"tls_rsa_with_aes_256_cbc_sha":                 "rsa",
	"tls_rsa_with_aes_128_cbc_sha":                 "rsa",
	"tls_rsa_with_3des_ede_cbc_sha":                "rsa",

	// ── PQC pre-standardisation names (SLH-DSA SPHINCS+ variants) ─────────────
	"sphincs+-sha256-128f-simple": "slh-dsa-sha2-128f",
	"sphincs+-sha256-128s-simple": "slh-dsa-sha2-128s",
	"sphincs+-sha256-192f-simple": "slh-dsa-sha2-192f",
	"sphincs+-sha256-192s-simple": "slh-dsa-sha2-192s",
	"sphincs+-sha256-256f-simple": "slh-dsa-sha2-256f",
	"sphincs+-sha256-256s-simple": "slh-dsa-sha2-256s",
	"sphincs+-shake-128f-simple":  "slh-dsa-shake-128f",
	"sphincs+-shake-128s-simple":  "slh-dsa-shake-128s",
	"sphincs+-shake-192f-simple":  "slh-dsa-shake-192f",
	"sphincs+-shake-192s-simple":  "slh-dsa-shake-192s",
	"sphincs+-shake-256f-simple":  "slh-dsa-shake-256f",
	"sphincs+-shake-256s-simple":  "slh-dsa-shake-256s",

	// ── PQC brand names → canonical standard names ────────────────────────────
	"crystals-kyber":     "ml-kem-768",  // default to 768 (NIST Level 3)
	"crystals-dilithium": "ml-dsa-65",   // default to level 3
	"kyber":              "ml-kem-768",
	"falcon":             "falcon-512",  // conservative: lower security level

	// ── OpenSSL mode-specific cipher names ───────────────────────────────────
	"aes-256-cfb":             "aes-256",
	"aes-256-cfb1":            "aes-256",
	"aes-256-cfb8":            "aes-256",
	"aes-256-ofb":             "aes-256",
	"aes-128-cfb":             "aes-128",
	"aes-128-ofb":             "aes-128",
	"camellia-256-cbc":        "camellia-256",
	"camellia-128-cbc":        "camellia-128",
	"aes-256-cbc-hmac-sha256": "aes-256-cbc",
	"aes-128-cbc-hmac-sha1":   "aes-128-cbc",

	// ── Named-curve aliases ─────────────────────────────────────────────────
	"p-192": "secp192r1",
	"p-224": "secp224r1",
	"k-283": "sect283k1",
	"k-409": "sect409k1",
	"k-571": "sect571k1",

	// ── SSH cipher / MAC names (RFC 4253 and common extensions) ─────────────
	"hmac-sha2-256": "hmac-sha256",
	"hmac-sha2-512": "hmac-sha512",
	"hmac-md5-96":   "hmac-md5",
	"arcfour":       "rc4",
	"arcfour128":    "rc4",
	"arcfour256":    "rc4",
	"blowfish-cbc":  "blowfish",
	"cast128-cbc":   "cast5",

	// ── GOST / Streebog aliases ─────────────────────────────────────────────
	"gost34.10":          "gost-r-34.10-2012",
	"gost3410":           "gost-r-34.10-2012",
	"streebog":           "streebog-256",
	"gost3411-2012-256":  "streebog-256",
	"gost3411-2012-512":  "streebog-512",

	// ── SHA truncated-variant spellings (FIPS 180-4) ────────────────────────
	"sha-512/224": "sha-512-224",
	"sha-512/256": "sha-512-256",
	"sha512-224":  "sha-512-224",
	"sha512-256":  "sha-512-256",
	"sha512/224":  "sha-512-224",
	"sha512/256":  "sha-512-256",

	// ── PQC short-name aliases ──────────────────────────────────────────────
	"ntru-hps": "ntru-hps-2048677",
	"ntru-hrss": "ntru-hrss-701",
	"mayo":     "mayo-1",
	"cross":    "cross-rsdp-128-small",
	"xmss":     "xmss-sha2-20-256",
	"lms":      "lms-sha256-m32-h25",
}
