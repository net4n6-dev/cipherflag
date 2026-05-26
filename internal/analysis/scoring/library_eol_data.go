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

// eolStarterMap lists library name+version prefixes known to be EOL.
// Match is by (lowercased library_name, version prefix via strings.HasPrefix).
// Extracted from library.go for maintainability.
var eolStarterMap = []struct {
	LibraryName   string
	VersionPrefix string
	Reason        string
}{
	// ── OpenSSL ────────────────────────────────────────────────────────────────
	{"openssl", "0.9.", "OpenSSL 0.9.x EOL 2010"},
	{"openssl", "1.0.", "OpenSSL 1.0.x EOL 2019-12-31"},
	{"openssl", "1.1.0", "OpenSSL 1.1.0 EOL 2019-09-11"},
	{"openssl", "1.1.1", "OpenSSL 1.1.1 LTS ended 2023-09-11"},
	{"openssl", "3.1.", "OpenSSL 3.1 EOL 2025-03-14"},

	// ── GnuTLS ────────────────────────────────────────────────────────────────
	{"gnutls", "2.", "GnuTLS 2.x fully superseded"},
	{"gnutls", "3.0.", "GnuTLS 3.0.x EOL 2014"},
	{"gnutls", "3.1.", "GnuTLS 3.1.x EOL 2014"},
	{"gnutls", "3.2.", "GnuTLS 3.2.x EOL 2017"},
	{"gnutls", "3.3.", "GnuTLS 3.3.x EOL 2018"},
	{"gnutls", "3.4.", "GnuTLS 3.4.x EOL 2019"},
	{"gnutls", "3.5.", "GnuTLS 3.5.x EOL 2019"},
	{"gnutls", "3.6.", "GnuTLS 3.6.x EOL 2023"},

	// ── libgcrypt ─────────────────────────────────────────────────────────────
	{"libgcrypt", "1.6.", "libgcrypt 1.6.x superseded"},
	{"libgcrypt", "1.7.", "libgcrypt 1.7.x superseded"},
	{"libgcrypt", "1.8.", "libgcrypt 1.8.x superseded by 1.10+"},

	// ── NSS ───────────────────────────────────────────────────────────────────
	// Dot-terminated prefixes prevent "3.1" from matching "3.101" (current ESR).
	{"nss", "3.10.", "NSS 3.1x series (pre-ESR)"},
	{"nss", "3.11.", "NSS 3.1x series (pre-ESR)"},
	{"nss", "3.12.", "NSS 3.1x series (pre-ESR)"},
	{"nss", "3.13.", "NSS 3.1x series (pre-ESR)"},
	{"nss", "3.14.", "NSS 3.1x series (pre-ESR)"},
	{"nss", "3.15.", "NSS 3.1x series (pre-ESR)"},
	{"nss", "3.16.", "NSS 3.1x series (pre-ESR)"},
	{"nss", "3.17.", "NSS 3.1x series (pre-ESR)"},
	{"nss", "3.18.", "NSS 3.1x series (pre-ESR)"},
	{"nss", "3.19.", "NSS 3.1x series (pre-ESR)"},
	{"nss", "3.2", "NSS 3.2x series (pre-ESR)"},
	{"nss", "3.3", "NSS 3.3x series (pre-ESR)"},
	{"nss", "3.4", "NSS 3.4x series (pre-ESR)"},
	{"nss", "3.5", "NSS 3.5x series (pre-ESR)"},
	{"nss", "3.67", "NSS pre-3.68 before ESR cycle"},

	// ── wolfSSL ───────────────────────────────────────────────────────────────
	{"wolfssl", "3.", "wolfSSL 3.x fully superseded"},
	{"wolfssl", "4.0", "wolfSSL 4.0.x superseded"},
	{"wolfssl", "4.1", "wolfSSL 4.1.x superseded"},
	{"wolfssl", "4.2", "wolfSSL 4.2.x superseded"},
	{"wolfssl", "4.3", "wolfSSL 4.3.x superseded"},
	{"wolfssl", "4.4", "wolfSSL 4.4.x superseded"},
	{"wolfssl", "4.5", "wolfSSL 4.5.x superseded"},
	{"wolfssl", "4.6", "wolfSSL 4.6.x superseded"},
	{"wolfssl", "4.7", "wolfSSL 4.7.x superseded"},
	{"wolfssl", "4.8", "wolfSSL 4.8.x superseded"},
	{"wolfssl", "5.0", "wolfSSL 5.0.x superseded"},
	{"wolfssl", "5.1", "wolfSSL 5.1.x superseded"},
	{"wolfssl", "5.2", "wolfSSL 5.2.x superseded"},
	{"wolfssl", "5.3", "wolfSSL 5.3.x superseded"},
	{"wolfssl", "5.4", "wolfSSL 5.4.x superseded"},

	// ── LibreSSL ──────────────────────────────────────────────────────────────
	{"libressl", "2.", "LibreSSL 2.x fully superseded"},
	{"libressl", "3.0.", "LibreSSL 3.0.x EOL"},
	{"libressl", "3.1.", "LibreSSL 3.1.x EOL"},
	{"libressl", "3.2.", "LibreSSL 3.2.x EOL"},
	{"libressl", "3.3.", "LibreSSL 3.3.x EOL"},
	{"libressl", "3.4.", "LibreSSL 3.4.x EOL"},
	{"libressl", "3.5.", "LibreSSL 3.5.x EOL"},
	{"libressl", "3.6.", "LibreSSL 3.6.x EOL"},
	{"libressl", "3.7.", "LibreSSL 3.7.x EOL"},

	// ── Mbed TLS ──────────────────────────────────────────────────────────────
	{"mbedtls", "2.", "Mbed TLS 2.x fully superseded by 3.x"},
	{"mbedtls", "3.0.", "Mbed TLS 3.0.x EOL"},
	{"mbedtls", "3.1.", "Mbed TLS 3.1.x EOL"},
	{"mbedtls", "3.2.", "Mbed TLS 3.2.x EOL"},
	{"mbedtls", "3.3.", "Mbed TLS 3.3.x EOL"},
	{"mbedtls", "3.4.", "Mbed TLS 3.4.x EOL"},
	{"mbedtls", "3.5.", "Mbed TLS 3.5.x superseded by 3.6 LTS"},

	// ── BouncyCastle ──────────────────────────────────────────────────────────
	// 1.70 is the first LTS baseline; 1.4x–1.6x are EOL.
	// Prefix "1.4" matches 1.40–1.49; "1.5" matches 1.50–1.59; "1.6" matches 1.60–1.69.
	{"bouncycastle", "1.4", "BouncyCastle 1.4x pre-LTS baseline"},
	{"bouncycastle", "1.5", "BouncyCastle 1.5x pre-LTS baseline"},
	{"bouncycastle", "1.6", "BouncyCastle 1.6x pre-1.70 LTS"},

	// ── Nettle ────────────────────────────────────────────────────────────────
	{"nettle", "2.", "Nettle 2.x fully superseded"},
	{"nettle", "3.0.", "Nettle 3.0.x EOL"},
	{"nettle", "3.1.", "Nettle 3.1.x EOL"},
	{"nettle", "3.2.", "Nettle 3.2.x EOL"},
	{"nettle", "3.3.", "Nettle 3.3.x EOL"},
	{"nettle", "3.4.", "Nettle 3.4.x EOL"},
	{"nettle", "3.5.", "Nettle 3.5.x EOL"},
	{"nettle", "3.6.", "Nettle 3.6.x EOL"},

	// ── PyCA cryptography (Python) ────────────────────────────────────────────
	// Project ships frequent breaking releases; anything below 42.x is superseded.
	{"cryptography", "1.", "PyCA cryptography 1.x EOL — upgrade to >=42.x"},
	{"cryptography", "2.", "PyCA cryptography 2.x EOL"},
	{"cryptography", "3.", "PyCA cryptography 3.x EOL"},
	{"cryptography", "36.", "PyCA cryptography 36.x superseded"},
	{"cryptography", "37.", "PyCA cryptography 37.x superseded"},
	{"cryptography", "38.", "PyCA cryptography 38.x superseded"},
	{"cryptography", "39.", "PyCA cryptography 39.x superseded"},
	{"cryptography", "40.", "PyCA cryptography 40.x superseded"},
	{"cryptography", "41.", "PyCA cryptography 41.x superseded"},

	// ── pycrypto (abandoned 2014) ─────────────────────────────────────────────
	// Empty VersionPrefix matches every version — the whole project is EOL.
	{"pycrypto", "", "pycrypto is entirely abandoned since 2014; migrate to pycryptodome or PyCA cryptography"},

	// ── pycryptodome ──────────────────────────────────────────────────────────
	{"pycryptodome", "3.0.", "pycryptodome 3.0.x superseded"},
	{"pycryptodome", "3.1.", "pycryptodome 3.1.x superseded"},
	{"pycryptodome", "3.2.", "pycryptodome 3.2.x superseded"},

	// ── pyopenssl ─────────────────────────────────────────────────────────────
	{"pyopenssl", "0.", "pyopenssl 0.x EOL"},
	{"pyopenssl", "16.", "pyopenssl 16.x EOL"},
	{"pyopenssl", "17.", "pyopenssl 17.x EOL"},
	{"pyopenssl", "18.", "pyopenssl 18.x EOL"},
	{"pyopenssl", "19.", "pyopenssl 19.x EOL"},

	// ── paramiko (Python SSH) ─────────────────────────────────────────────────
	{"paramiko", "1.", "paramiko 1.x EOL — upgrade to >=3.x for security patches"},
	{"paramiko", "2.0.", "paramiko 2.0.x EOL"},
	{"paramiko", "2.1.", "paramiko 2.1.x EOL"},
	{"paramiko", "2.2.", "paramiko 2.2.x EOL"},

	// ── libssh ────────────────────────────────────────────────────────────────
	{"libssh", "0.7.", "libssh 0.7.x EOL"},
	{"libssh", "0.8.", "libssh 0.8.x EOL"},
	{"libssh", "0.9.", "libssh 0.9.x EOL"},

	// ── libssh2 ───────────────────────────────────────────────────────────────
	{"libssh2", "1.7.", "libssh2 1.7.x EOL"},
	{"libssh2", "1.8.", "libssh2 1.8.x EOL"},

	// ── Botan (C++) ───────────────────────────────────────────────────────────
	{"botan", "1.", "Botan 1.x EOL"},
	{"botan", "2.0.", "Botan 2.0.x superseded"},
	{"botan", "2.1.", "Botan 2.1.x superseded"},
	{"botan", "2.2.", "Botan 2.2.x superseded"},
	{"botan", "2.3.", "Botan 2.3.x superseded"},

	// ── Crypto++ / cryptopp ───────────────────────────────────────────────────
	{"cryptopp", "5.", "Crypto++ 5.x fully superseded"},
	{"cryptopp", "6.0.", "Crypto++ 6.0.x superseded"},
	{"cryptopp", "6.1.", "Crypto++ 6.1.x superseded"},
	{"cryptopp", "7.0.", "Crypto++ 7.0.x superseded"},

	// ── Rust: ring ────────────────────────────────────────────────────────────
	{"ring", "0.12.", "ring 0.12.x EOL"},
	{"ring", "0.13.", "ring 0.13.x EOL"},
	{"ring", "0.14.", "ring 0.14.x EOL"},
	{"ring", "0.15.", "ring 0.15.x EOL"},
	{"ring", "0.16.", "ring 0.16.x EOL"},

	// ── Rust: rustls ──────────────────────────────────────────────────────────
	// Prefix "0.1" matches 0.1-0.19; "0.20." matches 0.20.x explicitly.
	// Modern rustls versions (0.21+) are NOT prefix-matched.
	{"rustls", "0.1", "rustls 0.1x EOL"},
	{"rustls", "0.20.", "rustls 0.20.x EOL"},

	// ── AWS s2n-tls ───────────────────────────────────────────────────────────
	{"s2n-tls", "0.", "s2n-tls 0.x pre-1.0 EOL"},

	// ── Apache MINA SSHD (Java) ───────────────────────────────────────────────
	{"apache-mina-sshd", "0.", "Apache MINA SSHD 0.x EOL"},
	{"apache-mina-sshd", "1.", "Apache MINA SSHD 1.x EOL"},

	// ── Fully abandoned / renamed projects (all versions EOL) ─────────────────
	{"polarssl", "", "PolarSSL renamed to Mbed TLS in 2015; migrate to Mbed TLS 3.6 LTS"},
	{"matrixssl", "", "MatrixSSL is EOL as of 2021"},
	{"axtls", "", "axTLS is abandoned since 2018"},
}
