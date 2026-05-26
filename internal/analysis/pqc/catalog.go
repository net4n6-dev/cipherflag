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

// canonical is the authoritative map of recognised algorithm names to
// their Classification. Keys are canonical (lowercased, no prefixes).
// Variant spellings live in the synonyms map and resolve through this one.
//
// Classification reasoning (for reviewers):
//   - Classical asymmetric (RSA/ECDSA/DH/ECDH/Ed25519/X25519/etc.) is
//     Vulnerable — Shor's algorithm breaks them with a sufficiently
//     capable quantum computer.
//   - Symmetric ciphers: Grover's algorithm halves effective strength.
//     128-bit keys (AES-128, ChaCha20) → Weakened (64-bit effective, still
//     practical). 256-bit keys (AES-256) → Safe (128-bit effective).
//     <128-bit keys (DES, 3DES) → Vulnerable.
//   - Hashes: Grover's halves collision resistance. SHA-256 → Weakened,
//     SHA-384/512 → Safe, MD5/SHA-1 → Vulnerable (classically broken).
//   - Signature composites (SHA256-RSA etc.) inherit the classical
//     signer's Vulnerability.
//   - KEX based on DH/ECDH is Vulnerable.
//   - KDFs are not meaningfully weakened by Grover's for realistic
//     parameter choices → Safe.
//   - NIST-standardised PQC (ML-KEM, ML-DSA, SLH-DSA, FALCON) → Safe.
//   - Hybrid KEMs (classical + PQC) → Hybrid.
var canonical = map[string]Classification{
	// ── Classical asymmetric (Vulnerable — Shor's) ─────────────────
	"rsa":     {Status: QuantumVulnerable, Canonical: "rsa", Category: CategoryAsymmetric},
	"dsa":     {Status: QuantumVulnerable, Canonical: "dsa", Category: CategoryAsymmetric},
	"dh":      {Status: QuantumVulnerable, Canonical: "dh", Category: CategoryAsymmetric},
	"ecdsa":   {Status: QuantumVulnerable, Canonical: "ecdsa", Category: CategoryAsymmetric},
	"ecdh":    {Status: QuantumVulnerable, Canonical: "ecdh", Category: CategoryAsymmetric},
	"ed25519": {Status: QuantumVulnerable, Canonical: "ed25519", Category: CategoryAsymmetric},
	"ed448":   {Status: QuantumVulnerable, Canonical: "ed448", Category: CategoryAsymmetric},
	"x25519":  {Status: QuantumVulnerable, Canonical: "x25519", Category: CategoryAsymmetric},
	"x448":    {Status: QuantumVulnerable, Canonical: "x448", Category: CategoryAsymmetric},

	// ── Symmetric ciphers ──────────────────────────────────────────
	// 128-bit effective strength (Weakened)
	"aes-128":           {Status: QuantumWeakened, Canonical: "aes-128", Category: CategorySymmetric},
	"aes-128-gcm":       {Status: QuantumWeakened, Canonical: "aes-128-gcm", Category: CategorySymmetric},
	"aes-128-cbc":       {Status: QuantumWeakened, Canonical: "aes-128-cbc", Category: CategorySymmetric},
	"aes-128-ctr":       {Status: QuantumWeakened, Canonical: "aes-128-ctr", Category: CategorySymmetric},
	"aes-192":           {Status: QuantumWeakened, Canonical: "aes-192", Category: CategorySymmetric},
	"aes-192-gcm":       {Status: QuantumWeakened, Canonical: "aes-192-gcm", Category: CategorySymmetric},
	"aes-192-cbc":       {Status: QuantumWeakened, Canonical: "aes-192-cbc", Category: CategorySymmetric},
	"chacha20":          {Status: QuantumWeakened, Canonical: "chacha20", Category: CategorySymmetric},
	"chacha20-poly1305": {Status: QuantumWeakened, Canonical: "chacha20-poly1305", Category: CategorySymmetric},
	// 256-bit effective strength (Safe under Grover's)
	"aes-256":     {Status: QuantumSafe, Canonical: "aes-256", Category: CategorySymmetric},
	"aes-256-gcm": {Status: QuantumSafe, Canonical: "aes-256-gcm", Category: CategorySymmetric},
	"aes-256-cbc": {Status: QuantumSafe, Canonical: "aes-256-cbc", Category: CategorySymmetric},
	"aes-256-ctr": {Status: QuantumSafe, Canonical: "aes-256-ctr", Category: CategorySymmetric},
	// Broken regardless of quantum
	"3des": {Status: QuantumVulnerable, Canonical: "3des", Category: CategorySymmetric},
	"des":  {Status: QuantumVulnerable, Canonical: "des", Category: CategorySymmetric},
	"rc4":  {Status: QuantumVulnerable, Canonical: "rc4", Category: CategorySymmetric},

	// ── Hash functions ─────────────────────────────────────────────
	"md5":      {Status: QuantumVulnerable, Canonical: "md5", Category: CategoryHash},
	"sha-1":    {Status: QuantumVulnerable, Canonical: "sha-1", Category: CategoryHash},
	"sha-224":  {Status: QuantumWeakened, Canonical: "sha-224", Category: CategoryHash},
	"sha-256":  {Status: QuantumWeakened, Canonical: "sha-256", Category: CategoryHash},
	"sha3-256": {Status: QuantumWeakened, Canonical: "sha3-256", Category: CategoryHash},
	"sha-384":  {Status: QuantumSafe, Canonical: "sha-384", Category: CategoryHash},
	"sha-512":  {Status: QuantumSafe, Canonical: "sha-512", Category: CategoryHash},
	"sha3-384": {Status: QuantumSafe, Canonical: "sha3-384", Category: CategoryHash},
	"sha3-512": {Status: QuantumSafe, Canonical: "sha3-512", Category: CategoryHash},

	// ── Signature composites (Vulnerable — classical signer dominates) ─
	"sha256-rsa":   {Status: QuantumVulnerable, Canonical: "sha256-rsa", Category: CategorySignature},
	"sha384-rsa":   {Status: QuantumVulnerable, Canonical: "sha384-rsa", Category: CategorySignature},
	"sha512-rsa":   {Status: QuantumVulnerable, Canonical: "sha512-rsa", Category: CategorySignature},
	"sha256-ecdsa": {Status: QuantumVulnerable, Canonical: "sha256-ecdsa", Category: CategorySignature},
	"sha384-ecdsa": {Status: QuantumVulnerable, Canonical: "sha384-ecdsa", Category: CategorySignature},
	"sha512-ecdsa": {Status: QuantumVulnerable, Canonical: "sha512-ecdsa", Category: CategorySignature},

	// ── Key exchange (Vulnerable — DH/ECDH base) ───────────────────
	"diffie-hellman-group14":               {Status: QuantumVulnerable, Canonical: "diffie-hellman-group14", Category: CategoryKEX},
	"diffie-hellman-group16":               {Status: QuantumVulnerable, Canonical: "diffie-hellman-group16", Category: CategoryKEX},
	"diffie-hellman-group18":               {Status: QuantumVulnerable, Canonical: "diffie-hellman-group18", Category: CategoryKEX},
	"diffie-hellman-group-exchange-sha256": {Status: QuantumVulnerable, Canonical: "diffie-hellman-group-exchange-sha256", Category: CategoryKEX},
	"ecdh-sha2-nistp256":                   {Status: QuantumVulnerable, Canonical: "ecdh-sha2-nistp256", Category: CategoryKEX},
	"ecdh-sha2-nistp384":                   {Status: QuantumVulnerable, Canonical: "ecdh-sha2-nistp384", Category: CategoryKEX},
	"ecdh-sha2-nistp521":                   {Status: QuantumVulnerable, Canonical: "ecdh-sha2-nistp521", Category: CategoryKEX},
	"curve25519-sha256":                    {Status: QuantumVulnerable, Canonical: "curve25519-sha256", Category: CategoryKEX},
	"curve448-sha512":                      {Status: QuantumVulnerable, Canonical: "curve448-sha512", Category: CategoryKEX},

	// ── KDFs (Safe) ────────────────────────────────────────────────
	"pbkdf2":   {Status: QuantumSafe, Canonical: "pbkdf2", Category: CategoryKDF},
	"hkdf":     {Status: QuantumSafe, Canonical: "hkdf", Category: CategoryKDF},
	"scrypt":   {Status: QuantumSafe, Canonical: "scrypt", Category: CategoryKDF},
	"argon2":   {Status: QuantumSafe, Canonical: "argon2", Category: CategoryKDF},
	"argon2id": {Status: QuantumSafe, Canonical: "argon2id", Category: CategoryKDF},

	// ── PQC KEMs (Safe — NIST FIPS 203) ────────────────────────────
	"ml-kem-512":  {Status: QuantumSafe, Canonical: "ml-kem-512", Category: CategoryPQCKEM, SecurityLevel: 1},
	"ml-kem-768":  {Status: QuantumSafe, Canonical: "ml-kem-768", Category: CategoryPQCKEM, SecurityLevel: 3},
	"ml-kem-1024": {Status: QuantumSafe, Canonical: "ml-kem-1024", Category: CategoryPQCKEM, SecurityLevel: 5},

	// ── PQC signatures (Safe — NIST FIPS 204, 205, forthcoming 206) ─
	"ml-dsa-44":         {Status: QuantumSafe, Canonical: "ml-dsa-44", Category: CategoryPQCSig, SecurityLevel: 2},
	"ml-dsa-65":         {Status: QuantumSafe, Canonical: "ml-dsa-65", Category: CategoryPQCSig, SecurityLevel: 3},
	"ml-dsa-87":         {Status: QuantumSafe, Canonical: "ml-dsa-87", Category: CategoryPQCSig, SecurityLevel: 5},
	// SLH-DSA (FIPS 205): s vs f is a speed/size trade-off, not a security level distinction.
	"slh-dsa-sha2-128s": {Status: QuantumSafe, Canonical: "slh-dsa-sha2-128s", Category: CategoryPQCSig, SecurityLevel: 1},
	"slh-dsa-sha2-128f": {Status: QuantumSafe, Canonical: "slh-dsa-sha2-128f", Category: CategoryPQCSig, SecurityLevel: 1},
	"slh-dsa-sha2-192s": {Status: QuantumSafe, Canonical: "slh-dsa-sha2-192s", Category: CategoryPQCSig, SecurityLevel: 3},
	"slh-dsa-sha2-192f": {Status: QuantumSafe, Canonical: "slh-dsa-sha2-192f", Category: CategoryPQCSig, SecurityLevel: 3},
	"slh-dsa-sha2-256s": {Status: QuantumSafe, Canonical: "slh-dsa-sha2-256s", Category: CategoryPQCSig, SecurityLevel: 5},
	"slh-dsa-sha2-256f": {Status: QuantumSafe, Canonical: "slh-dsa-sha2-256f", Category: CategoryPQCSig, SecurityLevel: 5},
	"falcon-512":        {Status: QuantumSafe, Canonical: "falcon-512", Category: CategoryPQCSig},
	"falcon-1024":       {Status: QuantumSafe, Canonical: "falcon-1024", Category: CategoryPQCSig},

	// ── Hybrid KEMs (classical + PQC) ──────────────────────────────
	"x25519-ml-kem-768": {Status: QuantumHybrid, Canonical: "x25519-ml-kem-768", Category: CategoryPQCKEM},
	"x448-ml-kem-1024":  {Status: QuantumHybrid, Canonical: "x448-ml-kem-1024", Category: CategoryPQCKEM},
	"p-256-ml-kem-768":  {Status: QuantumHybrid, Canonical: "p-256-ml-kem-768", Category: CategoryPQCKEM},
	"p-384-ml-kem-1024": {Status: QuantumHybrid, Canonical: "p-384-ml-kem-1024", Category: CategoryPQCKEM},

	// ── Generic AES mode-only names (key size unknown → conservative: Weakened) ─
	"aes-gcm":     {Status: QuantumWeakened, Canonical: "aes-gcm", Category: CategorySymmetric},
	"aes-ccm":     {Status: QuantumWeakened, Canonical: "aes-ccm", Category: CategorySymmetric},
	"aes-cbc":     {Status: QuantumWeakened, Canonical: "aes-cbc", Category: CategorySymmetric},
	"aes-ctr":     {Status: QuantumWeakened, Canonical: "aes-ctr", Category: CategorySymmetric},
	"aes-xts":     {Status: QuantumWeakened, Canonical: "aes-xts", Category: CategorySymmetric},

	// ── AES with key-size + additional modes ────────────────────────────────
	"aes-128-ccm": {Status: QuantumWeakened, Canonical: "aes-128-ccm", Category: CategorySymmetric},
	"aes-256-ccm": {Status: QuantumSafe, Canonical: "aes-256-ccm", Category: CategorySymmetric},
	"aes-128-xts": {Status: QuantumWeakened, Canonical: "aes-128-xts", Category: CategorySymmetric},
	"aes-256-xts": {Status: QuantumSafe, Canonical: "aes-256-xts", Category: CategorySymmetric},

	// ── Camellia (128-bit block; 256-bit key → Safe) ─────────────────────────
	"camellia-128": {Status: QuantumWeakened, Canonical: "camellia-128", Category: CategorySymmetric},
	"camellia-192": {Status: QuantumWeakened, Canonical: "camellia-192", Category: CategorySymmetric},
	"camellia-256": {Status: QuantumSafe, Canonical: "camellia-256", Category: CategorySymmetric},

	// ── ARIA (South Korean standard; same key-strength logic as AES) ─────────
	"aria-128": {Status: QuantumWeakened, Canonical: "aria-128", Category: CategorySymmetric},
	"aria-192": {Status: QuantumWeakened, Canonical: "aria-192", Category: CategorySymmetric},
	"aria-256": {Status: QuantumSafe, Canonical: "aria-256", Category: CategorySymmetric},

	// ── SM4 (Chinese standard, 128-bit block) ────────────────────────────────
	"sm4": {Status: QuantumWeakened, Canonical: "sm4", Category: CategorySymmetric},

	// ── SEED (South Korean 128-bit block cipher) ─────────────────────────────
	"seed": {Status: QuantumWeakened, Canonical: "seed", Category: CategorySymmetric},

	// ── Legacy / deprecated symmetric ────────────────────────────────────────
	"blowfish": {Status: QuantumVulnerable, Canonical: "blowfish", Category: CategorySymmetric},
	"cast5":    {Status: QuantumVulnerable, Canonical: "cast5", Category: CategorySymmetric},
	"idea":     {Status: QuantumVulnerable, Canonical: "idea", Category: CategorySymmetric},
	"rc2":      {Status: QuantumVulnerable, Canonical: "rc2", Category: CategorySymmetric},

	// ── Cipher-based MACs ────────────────────────────────────────────────────
	"cmac-aes": {Status: QuantumWeakened, Canonical: "cmac-aes", Category: CategorySymmetric},
	"gmac":     {Status: QuantumWeakened, Canonical: "gmac", Category: CategorySymmetric},

	// ── Additional hash functions ────────────────────────────────────────────
	"md2":         {Status: QuantumVulnerable, Canonical: "md2", Category: CategoryHash},
	"md4":         {Status: QuantumVulnerable, Canonical: "md4", Category: CategoryHash},
	"sha-0":       {Status: QuantumVulnerable, Canonical: "sha-0", Category: CategoryHash},
	"ripemd-160":  {Status: QuantumWeakened, Canonical: "ripemd-160", Category: CategoryHash},
	"sha3-224":    {Status: QuantumWeakened, Canonical: "sha3-224", Category: CategoryHash},
	"shake-128":   {Status: QuantumWeakened, Canonical: "shake-128", Category: CategoryHash},
	"shake-256":   {Status: QuantumSafe, Canonical: "shake-256", Category: CategoryHash},
	"blake2b-256": {Status: QuantumWeakened, Canonical: "blake2b-256", Category: CategoryHash},
	"blake2b-384": {Status: QuantumSafe, Canonical: "blake2b-384", Category: CategoryHash},
	"blake2b-512": {Status: QuantumSafe, Canonical: "blake2b-512", Category: CategoryHash},
	"blake2s-256": {Status: QuantumWeakened, Canonical: "blake2s-256", Category: CategoryHash},
	"blake3": {Status: QuantumWeakened, Canonical: "blake3", Category: CategoryHash}, // standard 256-bit output → 128-bit collision post-Grover; analogous to SHA-256
	"sm3":         {Status: QuantumWeakened, Canonical: "sm3", Category: CategoryHash},

	// ── HMAC (classified by underlying hash) ─────────────────────────────────
	"hmac-md5":    {Status: QuantumVulnerable, Canonical: "hmac-md5", Category: CategoryHash},
	"hmac-sha1":   {Status: QuantumVulnerable, Canonical: "hmac-sha1", Category: CategoryHash},
	"hmac-sha256": {Status: QuantumWeakened, Canonical: "hmac-sha256", Category: CategoryHash},
	"hmac-sha384": {Status: QuantumSafe, Canonical: "hmac-sha384", Category: CategoryHash},
	"hmac-sha512": {Status: QuantumSafe, Canonical: "hmac-sha512", Category: CategoryHash},

	// ── KDF additions ────────────────────────────────────────────────────────
	"bcrypt":         {Status: QuantumSafe, Canonical: "bcrypt", Category: CategoryKDF},
	"ansi-x963-kdf":  {Status: QuantumSafe, Canonical: "ansi-x963-kdf", Category: CategoryKDF},
	"concat-kdf":     {Status: QuantumSafe, Canonical: "concat-kdf", Category: CategoryKDF},
	"sp800-108-kdf": {Status: QuantumSafe, Canonical: "sp800-108-kdf", Category: CategoryKDF},

	// ── KEX — named curves ───────────────────────────────────────────────────
	"ecdh-p256":            {Status: QuantumVulnerable, Canonical: "ecdh-p256", Category: CategoryKEX},
	"ecdh-p384":            {Status: QuantumVulnerable, Canonical: "ecdh-p384", Category: CategoryKEX},
	"ecdh-p521":            {Status: QuantumVulnerable, Canonical: "ecdh-p521", Category: CategoryKEX},
	"ecdh-brainpoolp256r1": {Status: QuantumVulnerable, Canonical: "ecdh-brainpoolp256r1", Category: CategoryKEX},
	"ecdh-brainpoolp384r1": {Status: QuantumVulnerable, Canonical: "ecdh-brainpoolp384r1", Category: CategoryKEX},
	"ecdh-brainpoolp512r1": {Status: QuantumVulnerable, Canonical: "ecdh-brainpoolp512r1", Category: CategoryKEX},

	// ── KEX — explicit DH group sizes ────────────────────────────────────────
	"dh-2048": {Status: QuantumVulnerable, Canonical: "dh-2048", Category: CategoryKEX},
	"dh-3072": {Status: QuantumVulnerable, Canonical: "dh-3072", Category: CategoryKEX},
	"dh-4096": {Status: QuantumVulnerable, Canonical: "dh-4096", Category: CategoryKEX},

	// ── Asymmetric additions ─────────────────────────────────────────────────
	"sm2":       {Status: QuantumVulnerable, Canonical: "sm2", Category: CategoryAsymmetric},
	"ed25519ph": {Status: QuantumVulnerable, Canonical: "ed25519ph", Category: CategoryAsymmetric},
	"ed448ph":   {Status: QuantumVulnerable, Canonical: "ed448ph", Category: CategoryAsymmetric},

	// ── Signature composite additions ────────────────────────────────────────
	"sha1-rsa":     {Status: QuantumVulnerable, Canonical: "sha1-rsa", Category: CategorySignature},
	"md5-rsa":      {Status: QuantumVulnerable, Canonical: "md5-rsa", Category: CategorySignature},
	"sha224-rsa":   {Status: QuantumVulnerable, Canonical: "sha224-rsa", Category: CategorySignature},
	"sha1-ecdsa":   {Status: QuantumVulnerable, Canonical: "sha1-ecdsa", Category: CategorySignature},
	"sha224-ecdsa": {Status: QuantumVulnerable, Canonical: "sha224-ecdsa", Category: CategorySignature},
	"sha1-dsa":     {Status: QuantumVulnerable, Canonical: "sha1-dsa", Category: CategorySignature},
	"sha256-dsa":   {Status: QuantumVulnerable, Canonical: "sha256-dsa", Category: CategorySignature},
	"sha512-dsa":   {Status: QuantumVulnerable, Canonical: "sha512-dsa", Category: CategorySignature},
	"sha256-sm2":   {Status: QuantumVulnerable, Canonical: "sha256-sm2", Category: CategorySignature},

	// ── PQC KEM candidates (NIST on-ramp / round 4) ──────────────────────────
	"bike-l1":          {Status: QuantumSafe, Canonical: "bike-l1", Category: CategoryPQCKEM},
	"bike-l2":          {Status: QuantumSafe, Canonical: "bike-l2", Category: CategoryPQCKEM},
	"bike-l3":          {Status: QuantumSafe, Canonical: "bike-l3", Category: CategoryPQCKEM},
	"hqc-128":          {Status: QuantumSafe, Canonical: "hqc-128", Category: CategoryPQCKEM},
	"hqc-192":          {Status: QuantumSafe, Canonical: "hqc-192", Category: CategoryPQCKEM},
	"hqc-256":          {Status: QuantumSafe, Canonical: "hqc-256", Category: CategoryPQCKEM},
	"frodokem-640":     {Status: QuantumSafe, Canonical: "frodokem-640", Category: CategoryPQCKEM},
	"frodokem-976":     {Status: QuantumSafe, Canonical: "frodokem-976", Category: CategoryPQCKEM},
	"frodokem-1344":    {Status: QuantumSafe, Canonical: "frodokem-1344", Category: CategoryPQCKEM},
	"ntruprime-761":    {Status: QuantumSafe, Canonical: "ntruprime-761", Category: CategoryPQCKEM},
	"ntruprime-857":    {Status: QuantumSafe, Canonical: "ntruprime-857", Category: CategoryPQCKEM},
	"mceliece-348864":  {Status: QuantumSafe, Canonical: "mceliece-348864", Category: CategoryPQCKEM},
	"mceliece-460896":  {Status: QuantumSafe, Canonical: "mceliece-460896", Category: CategoryPQCKEM},
	"mceliece-6688128": {Status: QuantumSafe, Canonical: "mceliece-6688128", Category: CategoryPQCKEM},

	// ── PQC Sig — SLH-DSA SHAKE variants (FIPS 205) ──────────────────────────
	// s vs f is a speed/size trade-off within each level; same SecurityLevel.
	"slh-dsa-shake-128s": {Status: QuantumSafe, Canonical: "slh-dsa-shake-128s", Category: CategoryPQCSig, SecurityLevel: 1},
	"slh-dsa-shake-128f": {Status: QuantumSafe, Canonical: "slh-dsa-shake-128f", Category: CategoryPQCSig, SecurityLevel: 1},
	"slh-dsa-shake-192s": {Status: QuantumSafe, Canonical: "slh-dsa-shake-192s", Category: CategoryPQCSig, SecurityLevel: 3},
	"slh-dsa-shake-192f": {Status: QuantumSafe, Canonical: "slh-dsa-shake-192f", Category: CategoryPQCSig, SecurityLevel: 3},
	"slh-dsa-shake-256s": {Status: QuantumSafe, Canonical: "slh-dsa-shake-256s", Category: CategoryPQCSig, SecurityLevel: 5},
	"slh-dsa-shake-256f": {Status: QuantumSafe, Canonical: "slh-dsa-shake-256f", Category: CategoryPQCSig, SecurityLevel: 5},

	// ── Named elliptic curves (SEC / NIST / Koblitz) ────────────────────────
	// Classified as Asymmetric because they appear standalone in CBOMs /
	// library inventories before they're bound to a specific ECDSA/ECDH use.
	"secp256k1": {Status: QuantumVulnerable, Canonical: "secp256k1", Category: CategoryAsymmetric},
	"secp192r1": {Status: QuantumVulnerable, Canonical: "secp192r1", Category: CategoryAsymmetric},
	"secp224r1": {Status: QuantumVulnerable, Canonical: "secp224r1", Category: CategoryAsymmetric},
	"sect283k1": {Status: QuantumVulnerable, Canonical: "sect283k1", Category: CategoryAsymmetric},
	"sect409k1": {Status: QuantumVulnerable, Canonical: "sect409k1", Category: CategoryAsymmetric},
	"sect571k1": {Status: QuantumVulnerable, Canonical: "sect571k1", Category: CategoryAsymmetric},

	// ── National / regional asymmetric standards ────────────────────────────
	"gost-r-34.10-2012": {Status: QuantumVulnerable, Canonical: "gost-r-34.10-2012", Category: CategoryAsymmetric}, // Russian signature
	"sm9":               {Status: QuantumVulnerable, Canonical: "sm9", Category: CategoryAsymmetric},               // Chinese identity-based (bilinear pairings → Shor-vulnerable)

	// ── Stream / block cipher additions ─────────────────────────────────────
	// Salsa20 / ChaCha family — 256-bit key → Weakened post-Grover.
	// ChaCha8 has known-reduced-round cryptanalysis below the 128-bit bar → Vulnerable.
	"salsa20":  {Status: QuantumWeakened, Canonical: "salsa20", Category: CategorySymmetric},
	"chacha12": {Status: QuantumWeakened, Canonical: "chacha12", Category: CategorySymmetric},
	"chacha8":  {Status: QuantumVulnerable, Canonical: "chacha8", Category: CategorySymmetric},
	"rc5":      {Status: QuantumVulnerable, Canonical: "rc5", Category: CategorySymmetric}, // broken by known classical attacks at common parameter sets
	// GOST 28147-89 — 256-bit key but 64-bit block; Sweet32-style attacks and
	// modern cryptanalysis classify it as Vulnerable in practice.
	"gost-28147-89": {Status: QuantumVulnerable, Canonical: "gost-28147-89", Category: CategorySymmetric},
	// Twofish — AES finalist, 128-bit block. Mode-only (no key size) is
	// conservatively Weakened; see aes-gcm precedent above.
	"twofish": {Status: QuantumWeakened, Canonical: "twofish", Category: CategorySymmetric},

	// ── Hash additions ──────────────────────────────────────────────────────
	// NIST FIPS 180-4 truncations.
	"sha-512-224": {Status: QuantumWeakened, Canonical: "sha-512-224", Category: CategoryHash}, // 224-bit output → 112-bit collision
	"sha-512-256": {Status: QuantumWeakened, Canonical: "sha-512-256", Category: CategoryHash}, // 256-bit output → 128-bit collision
	// Legacy.
	"tiger":     {Status: QuantumVulnerable, Canonical: "tiger", Category: CategoryHash},     // 192-bit → 96-bit collision under Grover
	"whirlpool": {Status: QuantumSafe, Canonical: "whirlpool", Category: CategoryHash},       // 512-bit digest → 256-bit collision
	// GOST R 34.11-2012 (Streebog).
	"streebog-256": {Status: QuantumWeakened, Canonical: "streebog-256", Category: CategoryHash},
	"streebog-512": {Status: QuantumSafe, Canonical: "streebog-512", Category: CategoryHash},
	// Keccak pre-standardisation (same bucketing as SHA-3 of the same width).
	"keccak-256": {Status: QuantumWeakened, Canonical: "keccak-256", Category: CategoryHash},
	"keccak-512": {Status: QuantumSafe, Canonical: "keccak-512", Category: CategoryHash},
	// NIST SP 800-185 keyed MACs over Keccak.
	"kmac-128": {Status: QuantumWeakened, Canonical: "kmac-128", Category: CategoryHash},
	"kmac-256": {Status: QuantumSafe, Canonical: "kmac-256", Category: CategoryHash},
	// HMAC over SHA-3 — inherits underlying digest strength.
	"hmac-sha3-256": {Status: QuantumWeakened, Canonical: "hmac-sha3-256", Category: CategoryHash},
	"hmac-sha3-512": {Status: QuantumSafe, Canonical: "hmac-sha3-512", Category: CategoryHash},

	// ── Signature composites — SHA-3 & SHAKE (RFC 8692) ─────────────────────
	"sha3-256-rsa":   {Status: QuantumVulnerable, Canonical: "sha3-256-rsa", Category: CategorySignature},
	"sha3-384-rsa":   {Status: QuantumVulnerable, Canonical: "sha3-384-rsa", Category: CategorySignature},
	"sha3-512-rsa":   {Status: QuantumVulnerable, Canonical: "sha3-512-rsa", Category: CategorySignature},
	"sha3-256-ecdsa": {Status: QuantumVulnerable, Canonical: "sha3-256-ecdsa", Category: CategorySignature},
	"sha3-384-ecdsa": {Status: QuantumVulnerable, Canonical: "sha3-384-ecdsa", Category: CategorySignature},
	"sha3-512-ecdsa": {Status: QuantumVulnerable, Canonical: "sha3-512-ecdsa", Category: CategorySignature},
	"shake256-rsa":   {Status: QuantumVulnerable, Canonical: "shake256-rsa", Category: CategorySignature},

	// ── KEX additions ───────────────────────────────────────────────────────
	"ecdh-brainpoolp224r1": {Status: QuantumVulnerable, Canonical: "ecdh-brainpoolp224r1", Category: CategoryKEX},
	"dh-8192":              {Status: QuantumVulnerable, Canonical: "dh-8192", Category: CategoryKEX},
	"ecdh-secp256k1":       {Status: QuantumVulnerable, Canonical: "ecdh-secp256k1", Category: CategoryKEX},

	// ── KDF additions ───────────────────────────────────────────────────────
	"x9.42-kdf":   {Status: QuantumSafe, Canonical: "x9.42-kdf", Category: CategoryKDF},
	"hkdf-sha256": {Status: QuantumSafe, Canonical: "hkdf-sha256", Category: CategoryKDF},
	"hkdf-sha384": {Status: QuantumSafe, Canonical: "hkdf-sha384", Category: CategoryKDF},

	// ── PQC KEMs — round-3 survivors (not NIST-selected but shipped in liboqs) ─
	"saber":             {Status: QuantumSafe, Canonical: "saber", Category: CategoryPQCKEM},
	"ntru-hps-2048677":  {Status: QuantumSafe, Canonical: "ntru-hps-2048677", Category: CategoryPQCKEM},
	"ntru-hrss-701":     {Status: QuantumSafe, Canonical: "ntru-hrss-701", Category: CategoryPQCKEM},

	// ── PQC Signatures — NIST 2024 on-ramp candidates ───────────────────────
	"mayo-1":               {Status: QuantumSafe, Canonical: "mayo-1", Category: CategoryPQCSig},
	"mayo-3":               {Status: QuantumSafe, Canonical: "mayo-3", Category: CategoryPQCSig},
	"mayo-5":               {Status: QuantumSafe, Canonical: "mayo-5", Category: CategoryPQCSig},
	"cross-rsdp-128-small": {Status: QuantumSafe, Canonical: "cross-rsdp-128-small", Category: CategoryPQCSig},
	"cross-rsdp-256-small": {Status: QuantumSafe, Canonical: "cross-rsdp-256-small", Category: CategoryPQCSig},

	// ── PQC Signatures — stateful hash-based (NIST SP 800-208, standardised) ─
	"xmss-sha2-20-256":      {Status: QuantumSafe, Canonical: "xmss-sha2-20-256", Category: CategoryPQCSig},
	"lms-sha256-m32-h25":    {Status: QuantumSafe, Canonical: "lms-sha256-m32-h25", Category: CategoryPQCSig},
}
