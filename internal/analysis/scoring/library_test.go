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

import (
	"strings"
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

func TestLIB003_EOLVersion(t *testing.T) {
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "openssl", Version: "1.0.2"}
	r := ScoreLibrary(lib, nil)
	if findFinding(r, "LIB-003") == nil {
		t.Error("LIB-003 did not fire for openssl 1.0.2 (EOL)")
	}
}

func TestLIB003_CurrentVersion(t *testing.T) {
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "openssl", Version: "3.0.8"}
	r := ScoreLibrary(lib, nil)
	if findFinding(r, "LIB-003") != nil {
		t.Error("LIB-003 fired for current openssl 3.0.8")
	}
}

func TestLIB004_NotPQCCapable(t *testing.T) {
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "openssl", Version: "1.1.1", PQCCapable: false}
	r := ScoreLibrary(lib, nil)
	if findFinding(r, "LIB-004") == nil {
		t.Error("LIB-004 did not fire for non-PQC library")
	}
}

func TestLIB004_PQCCapable(t *testing.T) {
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "openssl", Version: "3.2.0", PQCCapable: true}
	r := ScoreLibrary(lib, nil)
	if findFinding(r, "LIB-004") != nil {
		t.Error("LIB-004 fired for PQC-capable library")
	}
}

func TestLIB005_FIPSValidated(t *testing.T) {
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "openssl", Version: "3.0.8"}
	r := ScoreLibrary(lib, nil)
	f := findFinding(r, "LIB-005")
	if f == nil {
		t.Error("LIB-005 did not fire for FIPS-validated openssl 3.0.8")
	} else if f.Severity != model.SeverityInfo {
		t.Errorf("LIB-005 severity = %s, want Info", f.Severity)
	}
}

func TestLIB005_NotFIPSValidated(t *testing.T) {
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "openssl", Version: "1.1.1"}
	r := ScoreLibrary(lib, nil)
	if findFinding(r, "LIB-005") != nil {
		t.Error("LIB-005 fired for non-FIPS version")
	}
}

func TestScoreLibrary_SetsAssetFields(t *testing.T) {
	lib := &model.CryptoLibrary{ID: "my-lib", LibraryName: "openssl", Version: "3.0.8"}
	r := ScoreLibrary(lib, nil)
	if r.AssetType != "crypto_library" {
		t.Errorf("AssetType = %s, want crypto_library", r.AssetType)
	}
	if r.AssetID != "my-lib" {
		t.Errorf("AssetID = %s, want my-lib", r.AssetID)
	}
}

func TestLIB003_BouncyCastleEOL(t *testing.T) {
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "bouncycastle", Version: "1.68"}
	r := ScoreLibrary(lib, nil)
	if findFinding(r, "LIB-003") == nil {
		t.Error("LIB-003 did not fire for bouncycastle 1.68 (pre-1.70 LTS)")
	}
}

func TestLIB003_BouncyCastleLTSCurrent(t *testing.T) {
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "bouncycastle", Version: "1.78"}
	r := ScoreLibrary(lib, nil)
	if findFinding(r, "LIB-003") != nil {
		t.Error("LIB-003 fired for current bouncycastle 1.78 (post-1.70 LTS)")
	}
}

func TestLIB003_NettleEOL(t *testing.T) {
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "nettle", Version: "3.2.1"}
	r := ScoreLibrary(lib, nil)
	if findFinding(r, "LIB-003") == nil {
		t.Error("LIB-003 did not fire for nettle 3.2.1 (EOL)")
	}
}

func TestLIB003_OpenSSL31EOL(t *testing.T) {
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "openssl", Version: "3.1.4"}
	r := ScoreLibrary(lib, nil)
	if findFinding(r, "LIB-003") == nil {
		t.Error("LIB-003 did not fire for openssl 3.1.4 (EOL 2025-03-14)")
	}
	fipsF := findFinding(r, "LIB-005")
	if fipsF != nil {
		t.Errorf("expected no LIB-005 for openssl 3.1.4 (EOL), got %+v", fipsF)
	}
}

func TestLIB003_NSS3101NotEOL(t *testing.T) {
	lib := &model.CryptoLibrary{ID: "nss-3101", LibraryName: "nss", Version: "3.101.0"}
	r := ScoreLibrary(lib, nil)
	f := findFinding(r, "LIB-003")
	if f != nil {
		t.Errorf("expected no LIB-003 for nss 3.101.0, got %+v", f)
	}
}

func TestLIB003_OpenSSL32NotEOL(t *testing.T) {
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "openssl", Version: "3.2.0"}
	r := ScoreLibrary(lib, nil)
	if findFinding(r, "LIB-003") != nil {
		t.Error("LIB-003 fired for openssl 3.2.0 (not EOL)")
	}
}

func TestLIB003_GnuTLS33EOL(t *testing.T) {
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "gnutls", Version: "3.3.30"}
	r := ScoreLibrary(lib, nil)
	if findFinding(r, "LIB-003") == nil {
		t.Error("LIB-003 did not fire for gnutls 3.3.30 (EOL 2018)")
	}
}

func TestLIB003_WolfSSL44EOL(t *testing.T) {
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "wolfssl", Version: "4.4.0"}
	r := ScoreLibrary(lib, nil)
	if findFinding(r, "LIB-003") == nil {
		t.Error("LIB-003 did not fire for wolfssl 4.4.0 (superseded)")
	}
}

// ─── 2026-04-18 pre-GA EOL expansion ─────────────────────────────────────────
// These cases cover the newly-added library families (Python, Rust, SSH,
// C++, and legacy/abandoned projects) plus extended coverage on existing
// families (Mbed TLS 3.x, wolfSSL 5.x, GnuTLS 3.6).

func TestLIB003_MbedTLS33EOL(t *testing.T) {
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "mbedtls", Version: "3.3.0"}
	if findFinding(ScoreLibrary(lib, nil), "LIB-003") == nil {
		t.Error("LIB-003 did not fire for mbedtls 3.3.0 (EOL)")
	}
}

func TestLIB003_MbedTLS36NotEOL(t *testing.T) {
	// Mbed TLS 3.6 is the current LTS; must NOT fire LIB-003.
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "mbedtls", Version: "3.6.2"}
	if findFinding(ScoreLibrary(lib, nil), "LIB-003") != nil {
		t.Error("LIB-003 incorrectly fired for mbedtls 3.6.2 (current LTS)")
	}
}

func TestLIB003_GnuTLS36EOL(t *testing.T) {
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "gnutls", Version: "3.6.16"}
	if findFinding(ScoreLibrary(lib, nil), "LIB-003") == nil {
		t.Error("LIB-003 did not fire for gnutls 3.6.16 (EOL 2023)")
	}
}

func TestLIB003_WolfSSL52EOL(t *testing.T) {
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "wolfssl", Version: "5.2.0"}
	if findFinding(ScoreLibrary(lib, nil), "LIB-003") == nil {
		t.Error("LIB-003 did not fire for wolfssl 5.2.0 (superseded)")
	}
}

func TestLIB003_PyCACryptography2EOL(t *testing.T) {
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "cryptography", Version: "2.9.2"}
	if findFinding(ScoreLibrary(lib, nil), "LIB-003") == nil {
		t.Error("LIB-003 did not fire for PyCA cryptography 2.9.2 (EOL)")
	}
}

func TestLIB003_PyCACryptography42NotEOL(t *testing.T) {
	// Modern PyCA cryptography (42+) must NOT match any prefix in the map.
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "cryptography", Version: "42.0.5"}
	if findFinding(ScoreLibrary(lib, nil), "LIB-003") != nil {
		t.Error("LIB-003 incorrectly fired for PyCA cryptography 42.0.5")
	}
}

func TestLIB003_PyCrypto_AnyVersionEOL(t *testing.T) {
	// pycrypto was abandoned in 2014; empty VersionPrefix matches any version.
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "pycrypto", Version: "2.6.1"}
	if findFinding(ScoreLibrary(lib, nil), "LIB-003") == nil {
		t.Error("LIB-003 did not fire for pycrypto 2.6.1 (abandoned)")
	}
}

func TestLIB003_Paramiko1EOL(t *testing.T) {
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "paramiko", Version: "1.18.5"}
	if findFinding(ScoreLibrary(lib, nil), "LIB-003") == nil {
		t.Error("LIB-003 did not fire for paramiko 1.18.5 (EOL)")
	}
}

func TestLIB003_LibSSH08EOL(t *testing.T) {
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "libssh", Version: "0.8.9"}
	if findFinding(ScoreLibrary(lib, nil), "LIB-003") == nil {
		t.Error("LIB-003 did not fire for libssh 0.8.9 (EOL)")
	}
}

func TestLIB003_Botan20EOL(t *testing.T) {
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "botan", Version: "2.0.1"}
	if findFinding(ScoreLibrary(lib, nil), "LIB-003") == nil {
		t.Error("LIB-003 did not fire for botan 2.0.1 (superseded)")
	}
}

func TestLIB003_Ring016EOL(t *testing.T) {
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "ring", Version: "0.16.20"}
	if findFinding(ScoreLibrary(lib, nil), "LIB-003") == nil {
		t.Error("LIB-003 did not fire for ring 0.16.20 (EOL)")
	}
}

func TestLIB003_Rustls022NotEOL(t *testing.T) {
	// rustls 0.22+ is current; 0.1x and 0.20 prefixes must not match "0.22.4".
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "rustls", Version: "0.22.4"}
	if findFinding(ScoreLibrary(lib, nil), "LIB-003") != nil {
		t.Error("LIB-003 incorrectly fired for rustls 0.22.4 (current)")
	}
}

func TestLIB003_PolarSSL_AnyVersionEOL(t *testing.T) {
	// PolarSSL renamed to Mbed TLS in 2015; every version is EOL.
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "polarssl", Version: "1.3.9"}
	if findFinding(ScoreLibrary(lib, nil), "LIB-003") == nil {
		t.Error("LIB-003 did not fire for polarssl 1.3.9 (renamed to Mbed TLS)")
	}
}

func TestLIB003_PyOpenSSL19EOL(t *testing.T) {
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "pyopenssl", Version: "19.1.0"}
	if findFinding(ScoreLibrary(lib, nil), "LIB-003") == nil {
		t.Error("LIB-003 did not fire for pyopenssl 19.1.0 (EOL)")
	}
}

func TestLIB005_MicrosoftCNG(t *testing.T) {
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "microsoft-cng", Version: "win11-22h2"}
	r := ScoreLibrary(lib, nil)
	f := findFinding(r, "LIB-005")
	if f == nil {
		t.Error("LIB-005 did not fire for microsoft-cng win11-22h2")
		return
	}
	if f.Severity != model.SeverityInfo {
		t.Errorf("LIB-005 severity = %s, want Info", f.Severity)
	}
	if f.Detail == "" {
		t.Error("LIB-005 Detail is empty; expected CMVP cert reference")
	}
}

func TestLIB005_MicrosoftCNGServer2022(t *testing.T) {
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "microsoft-cng", Version: "server2022"}
	r := ScoreLibrary(lib, nil)
	if findFinding(r, "LIB-005") == nil {
		t.Error("LIB-005 did not fire for microsoft-cng server2022")
	}
}

func TestLIB005_JavaSunJCE11(t *testing.T) {
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "java-sunjce", Version: "11.0.9"}
	r := ScoreLibrary(lib, nil)
	f := findFinding(r, "LIB-005")
	if f == nil {
		t.Error("LIB-005 did not fire for java-sunjce 11.0.9")
		return
	}
	if f.Severity != model.SeverityInfo {
		t.Errorf("LIB-005 severity = %s, want Info", f.Severity)
	}
}

func TestLIB005_JavaSunJCE17(t *testing.T) {
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "java-sunjce", Version: "17.0.1"}
	r := ScoreLibrary(lib, nil)
	if findFinding(r, "LIB-005") == nil {
		t.Error("LIB-005 did not fire for java-sunjce 17.0.1")
	}
}

func TestLIB005_WolfSSL57(t *testing.T) {
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "wolfssl", Version: "5.7.0"}
	r := ScoreLibrary(lib, nil)
	if findFinding(r, "LIB-005") == nil {
		t.Error("LIB-005 did not fire for wolfssl 5.7.0")
	}
}

func TestLIB005_NSS3101(t *testing.T) {
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "nss", Version: "3.101.0"}
	r := ScoreLibrary(lib, nil)
	if findFinding(r, "LIB-005") == nil {
		t.Error("LIB-005 did not fire for nss 3.101.0")
	}
}

// ─── 2026-04-18 pre-GA FIPS map expansion ────────────────────────────────────
// Cases covering commercial, HSM, and distribution-specific FIPS builds added
// during the pre-GA CMVP sync.

func TestLIB005_OpenSSLRHELFipsBuild(t *testing.T) {
	// RHEL 7 ships the "1.0.2k-fips" suffix — distro-patched FIPS build.
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "openssl", Version: "1.0.2k-fips"}
	if findFinding(ScoreLibrary(lib, nil), "LIB-005") == nil {
		t.Error("LIB-005 did not fire for openssl 1.0.2k-fips (RHEL 7)")
	}
}

func TestLIB005_OpenSSLStock102NotFIPS(t *testing.T) {
	// Stock OpenSSL 1.0.2 (no -fips suffix) is NOT a FIPS build; must NOT fire.
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "openssl", Version: "1.0.2k"}
	if findFinding(ScoreLibrary(lib, nil), "LIB-005") != nil {
		t.Error("LIB-005 incorrectly fired for stock openssl 1.0.2k (no FIPS suffix)")
	}
}

func TestLIB005_AWSLC(t *testing.T) {
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "aws-lc", Version: "1.12.0"}
	if findFinding(ScoreLibrary(lib, nil), "LIB-005") == nil {
		t.Error("LIB-005 did not fire for aws-lc 1.12.0")
	}
}

func TestLIB005_BoringCrypto(t *testing.T) {
	// Empty VersionPrefix matches any version of boringcrypto.
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "boringcrypto", Version: "go1.22-boring"}
	if findFinding(ScoreLibrary(lib, nil), "LIB-005") == nil {
		t.Error("LIB-005 did not fire for boringcrypto any-version")
	}
}

func TestLIB005_IBMJCE(t *testing.T) {
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "ibm-jce", Version: "11.0.20"}
	if findFinding(ScoreLibrary(lib, nil), "LIB-005") == nil {
		t.Error("LIB-005 did not fire for ibm-jce 11.0.20")
	}
}

func TestLIB005_RSABSAFE(t *testing.T) {
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "rsa-bsafe", Version: "7.1"}
	if findFinding(ScoreLibrary(lib, nil), "LIB-005") == nil {
		t.Error("LIB-005 did not fire for rsa-bsafe")
	}
}

func TestLIB005_ThalesLunaHSM(t *testing.T) {
	// HSM client libraries match by library name alone (empty VersionPrefix).
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "thales-luna", Version: "10.7.0"}
	if findFinding(ScoreLibrary(lib, nil), "LIB-005") == nil {
		t.Error("LIB-005 did not fire for thales-luna HSM client")
	}
}

func TestLIB005_MicrosoftCNGServer2016(t *testing.T) {
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "microsoft-cng", Version: "server2016"}
	if findFinding(ScoreLibrary(lib, nil), "LIB-005") == nil {
		t.Error("LIB-005 did not fire for microsoft-cng server2016")
	}
}

func TestLIB005_UnknownWindowsVersion(t *testing.T) {
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "microsoft-cng", Version: "win8"}
	r := ScoreLibrary(lib, nil)
	if findFinding(r, "LIB-005") != nil {
		t.Error("LIB-005 should not fire for unrecognised microsoft-cng version win8")
	}
}

func TestLIB001_CriticalCVE(t *testing.T) {
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "openssl", Version: "1.0.1c"}
	cves := []model.CryptoLibraryCVE{
		{LibraryName: "openssl", VersionRange: ">=1.0.1 <1.0.1g", CVEID: "CVE-2014-0160", Severity: "Critical", Description: "Heartbleed"},
	}
	r := ScoreLibrary(lib, cves)
	f := findFinding(r, "LIB-001")
	if f == nil {
		t.Fatal("LIB-001 did not fire for critical CVE")
	}
	if !f.ImmediateFail {
		t.Error("LIB-001 ImmediateFail should be true")
	}
	if f.Deduction != 50 {
		t.Errorf("LIB-001 Deduction = %d, want 50", f.Deduction)
	}
	if r.Grade != string(model.GradeF) {
		t.Errorf("Grade = %s, want F for ImmediateFail", r.Grade)
	}
}

func TestLIB001_MultiCritical_SingleFinding(t *testing.T) {
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "openssl", Version: "3.0.5"}
	cves := []model.CryptoLibraryCVE{
		{LibraryName: "openssl", VersionRange: ">=3.0.0 <3.0.7", CVEID: "CVE-2022-3602", Severity: "Critical", Description: "Punycode overflow"},
		{LibraryName: "openssl", VersionRange: ">=3.0.0 <3.0.7", CVEID: "CVE-2022-3786", Severity: "Critical", Description: "Punycode email overflow"},
	}
	r := ScoreLibrary(lib, cves)
	var count int
	for _, f := range r.Findings {
		if f.RuleID == "LIB-001" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 LIB-001 finding, got %d", count)
	}
	f := findFinding(r, "LIB-001")
	if f == nil {
		t.Fatal("LIB-001 not found")
	}
	if !strings.Contains(f.Detail, "CVE-2022-3602") {
		t.Errorf("Detail %q should contain CVE-2022-3602", f.Detail)
	}
	if !strings.Contains(f.Detail, "CVE-2022-3786") {
		t.Errorf("Detail %q should contain CVE-2022-3786", f.Detail)
	}
}

func TestLIB001_SuppressesLIB002(t *testing.T) {
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "openssl", Version: "1.0.1c"}
	cves := []model.CryptoLibraryCVE{
		{LibraryName: "openssl", VersionRange: ">=1.0.1 <1.0.1g", CVEID: "CVE-2014-0160", Severity: "Critical", Description: "Heartbleed"},
		{LibraryName: "openssl", VersionRange: ">=1.0.1 <1.0.1z", CVEID: "CVE-2014-9999", Severity: "High", Description: "hypothetical high"},
	}
	r := ScoreLibrary(lib, cves)
	if findFinding(r, "LIB-001") == nil {
		t.Error("LIB-001 should fire")
	}
	if findFinding(r, "LIB-002") != nil {
		t.Error("LIB-002 should NOT fire when LIB-001 fires")
	}
}

func TestLIB002_HighCVE(t *testing.T) {
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "openssl", Version: "3.0.5"}
	cves := []model.CryptoLibraryCVE{
		{LibraryName: "openssl", VersionRange: ">=3.0.0 <3.0.8", CVEID: "CVE-2023-0286", Severity: "High", Description: "GeneralName confusion"},
	}
	r := ScoreLibrary(lib, cves)
	f := findFinding(r, "LIB-002")
	if f == nil {
		t.Fatal("LIB-002 did not fire for high CVE")
	}
	if f.ImmediateFail {
		t.Error("LIB-002 ImmediateFail should be false")
	}
	if f.Deduction != 25 {
		t.Errorf("LIB-002 Deduction = %d, want 25", f.Deduction)
	}
	if r.Grade == string(model.GradeF) {
		t.Error("Grade should not be F for LIB-002 alone")
	}
}

func TestLIB002_MediumCVE(t *testing.T) {
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "gnutls", Version: "3.7.5"}
	cves := []model.CryptoLibraryCVE{
		{LibraryName: "gnutls", VersionRange: ">=3.6.0 <3.8.3", CVEID: "CVE-2024-0553", Severity: "Medium", Description: "RSA-PSK timing"},
	}
	r := ScoreLibrary(lib, cves)
	if findFinding(r, "LIB-002") == nil {
		t.Fatal("LIB-002 did not fire for medium CVE")
	}
}

func TestLIBCVE_NoMatch(t *testing.T) {
	cves := []model.CryptoLibraryCVE{
		{LibraryName: "openssl", VersionRange: ">=3.0.0 <3.0.7", CVEID: "CVE-2022-3602", Severity: "Critical", Description: "Punycode"},
	}
	// Confirm the CVE fires for an in-range version (validates that the implementation is running).
	libVuln := &model.CryptoLibrary{ID: "x", LibraryName: "openssl", Version: "3.0.5"}
	if findFinding(ScoreLibrary(libVuln, cves), "LIB-001") == nil {
		t.Fatal("LIB-001 did not fire for in-range version 3.0.5 (test setup check)")
	}
	// Now confirm the patched version does NOT fire.
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "openssl", Version: "3.0.9"}
	r := ScoreLibrary(lib, cves)
	if findFinding(r, "LIB-001") != nil {
		t.Error("LIB-001 should not fire for patched version 3.0.9")
	}
	if findFinding(r, "LIB-002") != nil {
		t.Error("LIB-002 should not fire for patched version 3.0.9")
	}
}

func TestLIBCVE_NilCVEs(t *testing.T) {
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "openssl", Version: "1.0.1c"}
	r := ScoreLibrary(lib, nil)
	if findFinding(r, "LIB-001") != nil || findFinding(r, "LIB-002") != nil {
		t.Error("nil CVE slice should produce no CVE findings")
	}
}

func TestLIBCVE_LowSeverityIgnored(t *testing.T) {
	lib := &model.CryptoLibrary{ID: "x", LibraryName: "openssl", Version: "1.0.1c"}
	// Confirm the matcher is running: a High CVE in the same range fires LIB-002.
	highCVEs := []model.CryptoLibraryCVE{
		{LibraryName: "openssl", VersionRange: ">=1.0.1 <1.0.1g", CVEID: "CVE-2014-HIGH", Severity: "High", Description: "hypothetical high"},
	}
	if findFinding(ScoreLibrary(lib, highCVEs), "LIB-002") == nil {
		t.Fatal("LIB-002 did not fire for High CVE (test setup check)")
	}
	// Now confirm a Low CVE in the same range does not fire.
	lowCVEs := []model.CryptoLibraryCVE{
		{LibraryName: "openssl", VersionRange: ">=1.0.1 <1.0.1g", CVEID: "CVE-2014-0000", Severity: "Low", Description: "low severity"},
	}
	r := ScoreLibrary(lib, lowCVEs)
	if findFinding(r, "LIB-001") != nil || findFinding(r, "LIB-002") != nil {
		t.Error("low severity CVE should produce no findings")
	}
}
