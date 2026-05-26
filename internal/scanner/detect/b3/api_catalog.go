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

// Package b3 detects crypto-API usage in source files (Go/Python/Java)
// and emits FindingRecords with CBOM metadata. The catalog below is
// intentionally small in v1; operators extend it by editing this file.
package b3

import "github.com/net4n6-dev/cipherflag/internal/scanner/finding"

// Language is the source language a rule applies to.
type Language string

const (
	LangGo     Language = "go"
	LangPython Language = "python"
	LangJava   Language = "java"
)

// CryptoAPIRule describes one (language, API) pair the detector recognises.
//
// Matching strategies vary by language:
//   - Go: (Import, Selector) — e.g. import "crypto/md5" + call md5.New()
//   - Python: (Import, Selector) — e.g. from cryptography.hazmat.primitives import hashes; hashes.MD5()
//   - Java: (ClassName, Selector, AlgorithmString) — e.g. MessageDigest.getInstance("MD5")
//
// Rules with non-empty AlgorithmString match only when the literal first
// argument equals AlgorithmString (or, for Cipher.getInstance, when the
// algorithm component of the slash-separated triple equals it).
type CryptoAPIRule struct {
	Language    Language
	RuleID      string
	Severity    string
	Algorithm   string
	Mode        string // "" if not applicable
	Padding     string // "" if not applicable
	KeySizeBits int    // 0 if unknown / runtime-determined
	OID         string // optional ASN.1 OID
	// Matchers (use the ones that apply to the language).
	Import          string // Go/Python: import path / module
	ClassName       string // Java: simple class name (e.g. "MessageDigest", "Cipher")
	Selector        string // method name (e.g. "New", "MD5", "getInstance")
	AlgorithmString string // Java: literal first arg to match
}

// Catalog is the v1 set of crypto-API rules.
var Catalog = []CryptoAPIRule{
	// ── Go ─────────────────────────────────────────────────────────────
	{Language: LangGo, RuleID: "CRYPTO-WEAK-HASH-MD5", Severity: finding.SeverityHigh,
		Algorithm: "MD5", Import: "crypto/md5", Selector: "New"},
	{Language: LangGo, RuleID: "CRYPTO-WEAK-HASH-MD5", Severity: finding.SeverityHigh,
		Algorithm: "MD5", Import: "crypto/md5", Selector: "Sum"},
	{Language: LangGo, RuleID: "CRYPTO-WEAK-HASH-SHA1", Severity: finding.SeverityHigh,
		Algorithm: "SHA1", Import: "crypto/sha1", Selector: "New"},
	{Language: LangGo, RuleID: "CRYPTO-WEAK-HASH-SHA1", Severity: finding.SeverityHigh,
		Algorithm: "SHA1", Import: "crypto/sha1", Selector: "Sum"},
	{Language: LangGo, RuleID: "CRYPTO-WEAK-CIPHER-DES", Severity: finding.SeverityHigh,
		Algorithm: "DES", Import: "crypto/des", Selector: "NewCipher"},
	{Language: LangGo, RuleID: "CRYPTO-WEAK-CIPHER-3DES", Severity: finding.SeverityHigh,
		Algorithm: "3DES", Import: "crypto/des", Selector: "NewTripleDESCipher"},
	{Language: LangGo, RuleID: "CRYPTO-WEAK-CIPHER-RC4", Severity: finding.SeverityHigh,
		Algorithm: "RC4", Import: "crypto/rc4", Selector: "NewCipher"},

	// ── Python ─────────────────────────────────────────────────────────
	// hashlib
	{Language: LangPython, RuleID: "CRYPTO-WEAK-HASH-MD5", Severity: finding.SeverityHigh,
		Algorithm: "MD5", Import: "hashlib", Selector: "md5"},
	{Language: LangPython, RuleID: "CRYPTO-WEAK-HASH-SHA1", Severity: finding.SeverityHigh,
		Algorithm: "SHA1", Import: "hashlib", Selector: "sha1"},
	// cryptography.hazmat.primitives.hashes
	{Language: LangPython, RuleID: "CRYPTO-WEAK-HASH-MD5", Severity: finding.SeverityHigh,
		Algorithm: "MD5", Import: "cryptography.hazmat.primitives.hashes", Selector: "MD5"},
	{Language: LangPython, RuleID: "CRYPTO-WEAK-HASH-SHA1", Severity: finding.SeverityHigh,
		Algorithm: "SHA1", Import: "cryptography.hazmat.primitives.hashes", Selector: "SHA1"},
	// cryptography.hazmat.primitives.ciphers.algorithms
	{Language: LangPython, RuleID: "CRYPTO-WEAK-CIPHER-DES", Severity: finding.SeverityHigh,
		Algorithm: "DES", Import: "cryptography.hazmat.primitives.ciphers.algorithms", Selector: "TripleDES"},
	// PyCrypto / PyCryptodome
	{Language: LangPython, RuleID: "CRYPTO-WEAK-CIPHER-DES", Severity: finding.SeverityHigh,
		Algorithm: "DES", Import: "Crypto.Cipher.DES", Selector: "new"},
	{Language: LangPython, RuleID: "CRYPTO-WEAK-CIPHER-3DES", Severity: finding.SeverityHigh,
		Algorithm: "3DES", Import: "Crypto.Cipher.DES3", Selector: "new"},
	{Language: LangPython, RuleID: "CRYPTO-WEAK-CIPHER-RC4", Severity: finding.SeverityHigh,
		Algorithm: "RC4", Import: "Crypto.Cipher.ARC4", Selector: "new"},

	// ── Java ───────────────────────────────────────────────────────────
	// JCA: MessageDigest.getInstance("MD5"|"SHA-1")
	{Language: LangJava, RuleID: "CRYPTO-WEAK-HASH-MD5", Severity: finding.SeverityHigh,
		Algorithm: "MD5", ClassName: "MessageDigest", Selector: "getInstance", AlgorithmString: "MD5"},
	{Language: LangJava, RuleID: "CRYPTO-WEAK-HASH-SHA1", Severity: finding.SeverityHigh,
		Algorithm: "SHA1", ClassName: "MessageDigest", Selector: "getInstance", AlgorithmString: "SHA-1"},
	// Cipher.getInstance("DES"|"DESede"|"RC4"|"DES/CBC/...")
	// AlgorithmString matches the algorithm portion (before first slash) of the literal.
	{Language: LangJava, RuleID: "CRYPTO-WEAK-CIPHER-DES", Severity: finding.SeverityHigh,
		Algorithm: "DES", ClassName: "Cipher", Selector: "getInstance", AlgorithmString: "DES"},
	{Language: LangJava, RuleID: "CRYPTO-WEAK-CIPHER-3DES", Severity: finding.SeverityHigh,
		Algorithm: "3DES", ClassName: "Cipher", Selector: "getInstance", AlgorithmString: "DESede"},
	{Language: LangJava, RuleID: "CRYPTO-WEAK-CIPHER-RC4", Severity: finding.SeverityHigh,
		Algorithm: "RC4", ClassName: "Cipher", Selector: "getInstance", AlgorithmString: "RC4"},
	// ECB mode flagged regardless of underlying cipher (catalog-side; detector
	// recognises the mode component of the JCA slash triple).
	{Language: LangJava, RuleID: "CRYPTO-WEAK-MODE-ECB", Severity: finding.SeverityMedium,
		Algorithm: "", Mode: "ECB", ClassName: "Cipher", Selector: "getInstance"},
}

// RulesByLanguage returns only the catalog entries for one language.
// Detectors call this once at construction time.
func RulesByLanguage(lang Language) []CryptoAPIRule {
	out := make([]CryptoAPIRule, 0, len(Catalog))
	for _, r := range Catalog {
		if r.Language == lang {
			out = append(out, r)
		}
	}
	return out
}
