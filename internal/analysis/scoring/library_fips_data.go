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

import "strings"

// fipsStarterMap lists library name+version prefixes known to have
// FIPS 140-2/140-3 validated builds. Match is by (lowercased library_name,
// version prefix via strings.HasPrefix). Extracted from library.go.
// FIPSLevel is the CDX wire-format level string ("fips140-2-l1", "fips140-3-l1",
// "fips140-3-l3", etc.); empty string signals "not validated at a specific level".
var fipsStarterMap = []struct {
	LibraryName   string
	VersionPrefix string
	Note          string
	FIPSLevel     string // CDX wire-format: "fips140-2-l1" | "fips140-3-l1" | "fips140-3-l3" | ""
}{
	// ── OpenSSL ────────────────────────────────────────────────────────────────
	{"openssl", "3.0.0", "OpenSSL 3.0 FIPS provider (CMVP #4282); requires explicit FIPS provider activation", "fips140-3-l1"},
	{"openssl", "3.0.8", "OpenSSL 3.0 FIPS provider later revision (CMVP #4282)", "fips140-3-l1"},
	{"openssl", "3.2.", "OpenSSL 3.2 FIPS provider", "fips140-3-l1"},

	// ── OpenSSL legacy FIPS object module ─────────────────────────────────────
	{"openssl-fips", "2.0.16", "OpenSSL FIPS Object Module 2.0 final (CMVP #1747)", "fips140-2-l1"},

	// ── wolfSSL ────────────────────────────────────────────────────────────────
	{"wolfssl", "4.7.0", "wolfCrypt FIPS 140-2 (CMVP #3389)", "fips140-2-l1"},
	{"wolfssl", "5.2.0", "wolfCrypt FIPS 140-3", "fips140-3-l1"},
	{"wolfssl", "5.6.0", "wolfCrypt FIPS 140-3 later revision", "fips140-3-l1"},
	{"wolfssl", "5.7.0", "wolfCrypt FIPS 140-3 later revision", "fips140-3-l1"},

	// ── BouncyCastle FIPS ──────────────────────────────────────────────────────
	{"bouncycastle-fips", "1.0.2.3", "BC FIPS Java 1.0.2.3 (CMVP #3673)", "fips140-2-l1"},
	{"bouncycastle-fips", "2.0.0", "BC FIPS Java 2.0.0 (CMVP 140-3)", "fips140-3-l1"},
	{"bouncycastle-fips", "2.0.3", "BC FIPS Java 2.0.3", "fips140-3-l1"},

	// ── NSS ────────────────────────────────────────────────────────────────────
	{"nss", "3.79", "NSS ESR FIPS validated (CMVP #4594)", "fips140-2-l1"},
	{"nss", "3.101", "NSS ESR FIPS validated", "fips140-2-l1"},

	// ── libgcrypt ──────────────────────────────────────────────────────────────
	{"libgcrypt", "1.8.5", "RHEL 8 FIPS-validated libgcrypt (CMVP #3765)", "fips140-2-l1"},
	{"libgcrypt", "1.10.", "libgcrypt 1.10.x FIPS validated", "fips140-2-l1"},

	// ── Mbed TLS ───────────────────────────────────────────────────────────────
	{"mbedtls", "2.28.", "Mbed TLS 2.28 LTS (FIPS builds via downstream; CMVP #4660)", "fips140-2-l1"},
	{"mbedtls", "3.6.", "Mbed TLS 3.6 LTS FIPS builds", "fips140-3-l1"},

	// ── Microsoft CNG (Windows platform provider) ─────────────────────────────
	// Version is the Windows release channel tag as reported by the crypto library ingester.
	{"microsoft-cng", "win10-1903", "[windows] Microsoft CNG FIPS 140-2 (CMVP #3197)", "fips140-2-l1"},
	{"microsoft-cng", "win10-2004", "[windows] Microsoft CNG FIPS 140-2 (CMVP #3644)", "fips140-2-l1"},
	{"microsoft-cng", "win10-21h2", "[windows] Microsoft CNG FIPS 140-3 (CMVP #4536)", "fips140-3-l1"},
	{"microsoft-cng", "win11-22h2", "[windows] Microsoft CNG FIPS 140-3 (CMVP #4491)", "fips140-3-l1"},
	{"microsoft-cng", "server2019", "[windows] Microsoft CNG FIPS 140-2 (CMVP #3197)", "fips140-2-l1"},
	{"microsoft-cng", "server2022", "[windows] Microsoft CNG FIPS 140-3 (CMVP #4536)", "fips140-3-l1"},

	// ── Java SunJCE ────────────────────────────────────────────────────────────
	// Version is the JDK version string as reported by the JVM.
	{"java-sunjce", "1.8.0_271", "[java] JDK 8 SunJCE FIPS 140-2 (CMVP #3514)", "fips140-2-l1"},
	{"java-sunjce", "11.0.9", "[java] JDK 11 SunJCE FIPS 140-2 (CMVP #3672)", "fips140-2-l1"},
	{"java-sunjce", "17.0.1", "[java] JDK 17 SunJCE FIPS 140-3 (CMVP #4642)", "fips140-3-l1"},
	{"java-sunjce", "21.0.1", "[java] JDK 21 SunJCE FIPS 140-3 (CMVP #4846)", "fips140-3-l1"},

	// ── Java SunJSSE (TLS layer) ───────────────────────────────────────────────
	{"java-sunjsse", "11.0.9", "[java] JDK 11 SunJSSE FIPS 140-2 (CMVP #3672)", "fips140-2-l1"},
	{"java-sunjsse", "17.0.1", "[java] JDK 17 SunJSSE FIPS 140-3 (CMVP #4642)", "fips140-3-l1"},

	// ── OpenSSL FIPS-tagged distribution builds ────────────────────────────────
	// Upstream OpenSSL 1.0.2 never had a FIPS-capable build by itself — downstream
	// distros (RHEL, SUSE, Oracle Linux) ship patched tarballs with "-fips" in the
	// version string. Matching on the exact suffix avoids tagging stock 1.0.2k etc.
	{"openssl", "1.0.2k-fips", "OpenSSL 1.0.2k-fips (RHEL 7 / CentOS 7; CMVP #1747)", "fips140-2-l1"},
	{"openssl", "1.0.2m-fips", "OpenSSL 1.0.2m-fips (commercial FIPS build)", "fips140-2-l1"},
	{"openssl", "1.0.2o-fips", "OpenSSL 1.0.2o-fips", "fips140-2-l1"},
	{"openssl", "1.0.2u-fips", "OpenSSL 1.0.2u-fips (RHEL 7 later revision)", "fips140-2-l1"},
	{"openssl", "1.1.1k-fips", "OpenSSL 1.1.1k-fips (RHEL 8)", "fips140-2-l1"},
	{"openssl", "3.0.7-fips", "OpenSSL 3.0.7-fips (RHEL 9 / CMVP #4282)", "fips140-3-l1"},
	{"openssl", "3.0.9-fips", "OpenSSL 3.0.9-fips", "fips140-3-l1"},

	// ── AWS LibCrypto (aws-lc) — fork of BoringSSL with FIPS validation ────────
	{"aws-lc", "1.", "AWS-LC 1.x FIPS 140-3 validated (CMVP #4631)", "fips140-3-l1"},
	{"aws-lc-fips", "2.", "AWS-LC-FIPS 2.x FIPS 140-3 (CMVP #4759)", "fips140-3-l1"},

	// ── Google BoringCrypto — FIPS-validated subset of BoringSSL ───────────────
	// BoringCrypto has no conventional versioning; empty prefix matches any
	// scanned instance with library_name="boringcrypto".
	{"boringcrypto", "", "Google BoringCrypto FIPS 140-2 (CMVP #3318 / FIPS 140-3 in progress)", "fips140-2-l1"},

	// ── IBM JCE (Semeru / IBM SDK for Java) ───────────────────────────────────
	{"ibm-jce", "8.", "[java] IBM JCE 8 FIPS 140-2 (CMVP #2711)", "fips140-2-l1"},
	{"ibm-jce", "11.", "[java] IBM JCE 11 FIPS 140-3 (Semeru Runtimes)", "fips140-3-l1"},

	// ── Commercial FIPS-validated libraries ────────────────────────────────────
	// Exact versioning varies; library-name alone is the operator signal.
	{"rsa-bsafe", "", "[commercial] RSA BSAFE Crypto-J FIPS 140-2 (Dell)", "fips140-2-l1"},
	{"dell-bsafe", "", "[commercial] Dell BSAFE Crypto-J FIPS 140-2", "fips140-2-l1"},
	{"cryptocomply", "", "[commercial] SafeLogic CryptoComply FIPS 140-2 / 140-3", "fips140-2-l1"},

	// ── HSM client libraries (PKCS#11 / vendor SDK surface) ───────────────────
	{"thales-luna", "", "[hsm] Thales Luna Network HSM 7 FIPS 140-3 Level 3", "fips140-3-l3"},
	{"entrust-nshield", "", "[hsm] Entrust nShield HSM FIPS 140-3 Level 3", "fips140-3-l3"},
	{"aws-cloudhsm", "", "[hsm] AWS CloudHSM PKCS#11 client (Luna-backed, FIPS 140-3 Level 3)", "fips140-3-l3"},
	{"azure-keyvault", "", "[hsm] Azure Key Vault Premium HSM FIPS 140-2 Level 2 (Managed HSM L3)", "fips140-2-l2"},
	{"yubico-yubihsm", "", "[hsm] YubiHSM 2 FIPS 140-3 Level 3", "fips140-3-l3"},

	// ── wolfSSH (separate module from wolfSSL) ─────────────────────────────────
	{"wolfssh", "1.4.15", "wolfSSH FIPS 140-3 (uses wolfCrypt FIPS)", "fips140-3-l1"},

	// ── wolfSSL FIPS — later patch revisions ───────────────────────────────────
	{"wolfssl", "5.6.4", "wolfCrypt FIPS 140-3 (CMVP #4718)", "fips140-3-l1"},
	{"wolfssl", "5.7.2", "wolfCrypt FIPS 140-3 later revision", "fips140-3-l1"},

	// ── NSS — additional FIPS-validated ESR releases ───────────────────────────
	{"nss", "3.90", "NSS 3.90 ESR FIPS validated", "fips140-2-l1"},
	{"nss", "3.112", "NSS 3.112 ESR FIPS validated", "fips140-2-l1"},

	// ── Microsoft CNG — additional Windows channel tags ───────────────────────
	// Historical channels still found in air-gapped / critical-infra estates.
	{"microsoft-cng", "win7", "[windows] Microsoft CNG FIPS 140-2 (CMVP #1327)", "fips140-2-l1"},
	{"microsoft-cng", "win8.1", "[windows] Microsoft CNG FIPS 140-2 (CMVP #2357)", "fips140-2-l1"},
	{"microsoft-cng", "win10-1809", "[windows] Microsoft CNG FIPS 140-2 (CMVP #3197)", "fips140-2-l1"},
	{"microsoft-cng", "server2016", "[windows] Microsoft CNG FIPS 140-2 (CMVP #2356)", "fips140-2-l1"},

	// ── Microsoft legacy CAPI (Windows XP/Vista/7 era) ────────────────────────
	{"microsoft-rsaenh", "", "[windows] Microsoft RSA Enhanced CSP legacy FIPS (CMVP #560)", "fips140-2-l1"},

	// ── Java SunJCE — additional LTS patch revisions ──────────────────────────
	{"java-sunjce", "21.0.5", "[java] JDK 21 SunJCE FIPS 140-3 later revision", "fips140-3-l1"},
}

// LibraryFIPSLevel returns the CDX wire-format FIPS level string for the
// given library name and version (e.g. "fips140-3-l1"), or "" when the
// library/version pair is not in the validated-build map.
//
// Match semantics mirror checkLibraryFIPS: case-insensitive library name
// + version-prefix match using strings.HasPrefix.
func LibraryFIPSLevel(libraryName, version string) string {
	name := strings.ToLower(libraryName)
	for _, entry := range fipsStarterMap {
		if entry.LibraryName == name && strings.HasPrefix(version, entry.VersionPrefix) {
			return entry.FIPSLevel
		}
	}
	return ""
}
